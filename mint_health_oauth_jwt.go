package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// `/mint-health-oauth-jwt` endpoint (Refs ippoan/auth-worker#209)
//
// auth-worker の `GET /health/oauth` は Bearer JWT (HS256, env.JWT_SECRET で
// 検証) を要求する。CI から定期的にこれを叩くには、同じ JWT_SECRET で署名済の
// 長期 token を 1 本作って GitHub Actions / Cloud Run env に登録する必要がある。
//
// 本 endpoint は以下を一括で行う:
//
//   1. GCP Secret Manager から `JWT_SECRET` の **値** を AccessSecretVersion で
//      取得 (= `secretValueGetter` 経由、5 分 TTL cache)。
//   2. payload `{"sub":"ci-health-oauth","exp":<now+1y>}` を HS256 で署名し
//      JWT 文字列を組み立てる。
//   3. `HEALTH_OAUTH_JWT` という名前の GCP Secret に書く (なければ
//      CreateSecret で新規作成、あれば AddSecretVersion で新 version 投入)。
//
// **JWT_SECRET の値も、組み立てた JWT も、応答 body や log には echo しない**。
// proxy memory の中に居る間だけ存在し、GCP Secret Manager に landing したら
// 以降は GCP IAM 経由でのみ accessible。
//
// 必要 IAM (operator step):
//
//   gcloud secrets add-iam-policy-binding JWT_SECRET \
//     --project=cloudsql-sv \
//     --member="serviceAccount:secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com" \
//     --role="roles/secretmanager.secretAccessor"
//
// この grant が無いと proxy は AccessSecretVersion で PermissionDenied を
// 受け、502 を返す。
//
// scope を狭めるため signing oracle にはしない:
//   - 入力 secret 名は hardcode (`JWT_SECRET`)
//   - 出力 secret 名は hardcode (`HEALTH_OAUTH_JWT`)
//   - payload claims も hardcode (`sub: "ci-health-oauth"`, exp = +1 year)
// 将来 別 JWT も mint したくなったら同 pattern で別 endpoint を切る。

const (
	mintInputSecretName  = "JWT_SECRET"
	mintOutputSecretName = "HEALTH_OAUTH_JWT"
	mintJwtSub           = "ci-health-oauth"
	mintJwtTtl           = 365 * 24 * time.Hour
	mintCallTimeout      = 20 * time.Second
)

type mintHealthOAuthJwtResponse struct {
	Ok         bool   `json:"ok"`
	SecretName string `json:"secret_name"`
	NewVersion string `json:"new_version"`
	Created    bool   `json:"created"`
	ExpiresAt  string `json:"expires_at"`
}

func handleMintHealthOAuthJwt(
	getter secretValueGetter,
	lister secretLister,
	projectID string,
	now func() time.Time,
) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))

		ctx, cancel := context.WithTimeout(r.Context(), mintCallTimeout)
		defer cancel()

		jwtSecret, err := getter.Get(ctx, mintInputSecretName)
		if err != nil {
			log.Printf("MINT_HEALTH_OAUTH_JWT read JWT_SECRET failed actor=%q err=%v", actor, err)
			http.Error(w, "upstream error", grpcToHTTPStatus(err))
			return
		}
		if jwtSecret == "" {
			log.Printf("MINT_HEALTH_OAUTH_JWT JWT_SECRET payload empty actor=%q", actor)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		issuedAt := now().UTC()
		expiresAt := issuedAt.Add(mintJwtTtl)
		token, err := signHS256Jwt(jwtSecret, mintJwtClaims(mintJwtSub, issuedAt, expiresAt))
		// jwtSecret は signHS256Jwt から戻った時点で参照不要 — Go GC に任せる。
		// 文字列を明示的に zeroize する手段は無いが、Cloud Run instance の
		// memory が複数 request で再利用される影響を最小化するため、ここで
		// 局所 scope を抜けるよう変数を意図的に shadow する。
		jwtSecret = ""
		_ = jwtSecret
		if err != nil {
			log.Printf("MINT_HEALTH_OAUTH_JWT sign failed actor=%q err=%v", actor, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// CreateSecret は idempotent (AlreadyExists → alreadyExists=true) なので
		// 初回 mint も rotation も同 path で扱える。
		parent := fmt.Sprintf("projects/%s", projectID)
		secretFullName, alreadyExists, err := lister.CreateSecret(ctx, parent, mintOutputSecretName)
		if err != nil {
			// AlreadyExists 以外の upstream error。CreateSecret 内部で
			// AlreadyExists は alreadyExists=true に正規化されるので
			// ここに来るのは真の上流エラー。
			if status.Code(err) == codes.PermissionDenied {
				log.Printf("MINT_HEALTH_OAUTH_JWT create permission denied actor=%q err=%v", actor, err)
				http.Error(w, "upstream permission denied (need secretCreator role on runtime SA)", grpcToHTTPStatus(err))
				return
			}
			log.Printf("MINT_HEALTH_OAUTH_JWT create failed actor=%q err=%v", actor, err)
			http.Error(w, "upstream error", grpcToHTTPStatus(err))
			return
		}

		newVersionName, err := lister.AddSecretVersion(ctx, secretFullName, []byte(token))
		// token は AddSecretVersion から戻った時点で参照不要。同じく shadow。
		token = ""
		_ = token
		if err != nil {
			log.Printf("MINT_HEALTH_OAUTH_JWT add-version failed actor=%q err=%v", actor, err)
			http.Error(w, "upstream error", grpcToHTTPStatus(err))
			return
		}

		log.Printf("MINT_HEALTH_OAUTH_JWT ok actor=%q target=%q created=%v new_version=%q",
			actor, mintOutputSecretName, !alreadyExists,
			sanitizeLogValue(newVersionName))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mintHealthOAuthJwtResponse{
			Ok:         true,
			SecretName: mintOutputSecretName,
			NewVersion: newVersionName,
			Created:    !alreadyExists,
			ExpiresAt:  expiresAt.Format(time.RFC3339),
		})
	})
}

// mintJwtClaims はテストで決定論にできるよう iat / exp を引数で受ける。
func mintJwtClaims(sub string, issuedAt, expiresAt time.Time) map[string]any {
	return map[string]any{
		"sub": sub,
		"iat": issuedAt.Unix(),
		"exp": expiresAt.Unix(),
	}
}

// signHS256Jwt は payload を HMAC-SHA256 で署名した RFC 7519 形式の JWT を返す。
// header は固定 `{"alg":"HS256","typ":"JWT"}`。秘密鍵は string で受けるが
// HMAC API は []byte を要求するので即変換。
func signHS256Jwt(secret string, claims map[string]any) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return "", fmt.Errorf("hmac write: %w", err)
	}
	sig := enc.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}
