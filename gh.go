package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// GitHub Actions org secrets proxy endpoints。worker (`secrets-inventory`)
// が直接 GitHub API を叩くのを廃止し、本 proxy 経由で `GCP_PROXY_API_KEY`
// 1 個だけ持てば済むようにする。Refs ippoan/secrets-inventory#45.
//
// 提供 endpoint:
//   - `GET /gh/secrets`        — org secrets list (inventory + 存在チェック)
//   - `PUT /gh/secrets/{name}` — value 更新 / 新規作成 (libsodium sealed box
//                                は proxy 側で実行 = worker は素の value を送る)
//
// GitHub PAT は Secret Manager から runtime 取得 (= worker 側に持たない)。
// 値は body の `value` field でのみ運び、log / response に echo しない。

const githubAPI = "https://api.github.com"

// ghPutBody は PUT body。`value` は **素の値** (= proxy 側で sealed box
// encrypt してから GitHub に渡す)。worker は libsodium 依存を持たない。
type ghPutBody struct {
	Value      string `json:"value"`
	Visibility string `json:"visibility,omitempty"`
}

type ghPutResponse struct {
	Ok      bool `json:"ok"`
	Created bool `json:"created"`
}

type ghRawSecret struct {
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Visibility string `json:"visibility,omitempty"`
}

type ghOrgSecretsResponse struct {
	TotalCount int           `json:"total_count"`
	Secrets    []ghRawSecret `json:"secrets"`
}

type ghListResponse struct {
	Secrets []ghRawSecret `json:"secrets"`
}

type ghPublicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

// ghConfig は GH endpoint 群が共有する設定。
// 2 field が **すべて** non-empty なら configured。1 つでも空なら未設定扱いで
// handler が 503 を返す (cf.go の cfConfig と同方針)。
type ghConfig struct {
	org         string
	tokenSecret string
}

func (c ghConfig) configured() bool {
	return c.org != "" && c.tokenSecret != ""
}

// ghNamePattern は GitHub Actions secret name の制約 (= `[A-Z_][A-Z0-9_]*`)
// に近い range で path injection を弾く。GitHub 側は SCREAMING_SNAKE 強制
// だが、本 proxy では `secretNamePattern` (= kebab も許容) を流用して
// validation し、SCREAMING_SNAKE 強制は GitHub API 側の 422 に委ねる。
func handleGhList(getter secretValueGetter, cfg ghConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("GH_LIST token fetch failed: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// pagination: per_page=100 で 100 ページまで (= 1 万件)。実 org は数十
		// 件なので 1 page で終わる想定。
		out := []ghRawSecret{}
		page := 1
		for ; page <= 100; page++ {
			url := fmt.Sprintf("%s/orgs/%s/actions/secrets?per_page=100&page=%d",
				githubAPI, cfg.org, page)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			req.Header.Set("User-Agent", "secrets-inventory-gcp")

			res, err := http_.Do(req)
			if err != nil {
				log.Printf("GH_LIST upstream network page=%d: %v", page, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			if res.StatusCode/100 != 2 {
				res.Body.Close()
				log.Printf("GH_LIST upstream %d page=%d", res.StatusCode, page)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			var resp ghOrgSecretsResponse
			if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
				res.Body.Close()
				log.Printf("GH_LIST decode page=%d: %v", page, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			res.Body.Close()
			out = append(out, resp.Secrets...)
			if len(resp.Secrets) < 100 {
				break
			}
		}
		if page > 100 {
			log.Printf("GH_LIST pagination exceeded 100 pages")
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ghListResponse{Secrets: out})
	})
}

// handleGhPut は `PUT /gh/secrets/{name}` のハンドラ。
//
// 1) public-key を fetch
// 2) sealed box encrypt (curve25519 + xsalsa20-poly1305 + blake2b nonce)
// 3) PUT で投入
//
// `X-Fail-If-Exists: true` (default false) を渡せば事前に
// `GET /orgs/{org}/actions/secrets/{name}` で 200/404 を確認し、200 のときは
// 409 で reject (= 新規 secret 用 guard)。GitHub の PUT は冪等で create と
// update を兼ねるため明示的な existence check が必要。
//
// 成功 response の `created` は **proxy 側では正確に判定不能** (= GitHub PUT
// 自体が created / updated を見分ける status 差を返さないことがある) ので、
// fail_if_exists=true (= 事前 check で 404 だった) のときは created=true、
// それ以外は created=false 固定で返す。worker 側はこれを「権威ある created
// flag」として扱う。
func handleGhPut(getter secretValueGetter, cfg ghConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/gh/secrets/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(name)

		failIfExists := false
		switch strings.ToLower(r.Header.Get("X-Fail-If-Exists")) {
		case "", "false", "0", "no":
			failIfExists = false
		case "true", "1", "yes":
			failIfExists = true
		default:
			http.Error(w, "invalid X-Fail-If-Exists", http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body ghPutBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if body.Value == "" {
			http.Error(w, "value is required", http.StatusBadRequest)
			return
		}
		if len(body.Value) > maxSecretValueBytes {
			http.Error(w, "value too large", http.StatusBadRequest)
			return
		}
		visibility := body.Visibility
		if visibility == "" {
			visibility = "all"
		}
		switch visibility {
		case "all", "private", "selected":
		default:
			http.Error(w, "invalid visibility", http.StatusBadRequest)
			return
		}

		log.Printf("GH_PUT requested actor=%q target=%q fail_if_exists=%v visibility=%q value_bytes=%d",
			actor, target, failIfExists, visibility, len(body.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("GH_PUT token fetch failed actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// existence check (fail_if_exists=true のみ)
		if failIfExists {
			url := fmt.Sprintf("%s/orgs/%s/actions/secrets/%s", githubAPI, cfg.org, name)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			req.Header.Set("User-Agent", "secrets-inventory-gcp")
			res, err := http_.Do(req)
			if err != nil {
				log.Printf("GH_PUT existence-check network actor=%q target=%q err=%v", actor, target, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				log.Printf("GH_PUT conflict actor=%q target=%q already exists", actor, target)
				http.Error(w, "secret already exists", http.StatusConflict)
				return
			}
			if res.StatusCode != http.StatusNotFound {
				log.Printf("GH_PUT existence-check upstream %d actor=%q target=%q",
					res.StatusCode, actor, target)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
		}

		// public key fetch
		pkURL := fmt.Sprintf("%s/orgs/%s/actions/secrets/public-key", githubAPI, cfg.org)
		pkReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, pkURL, nil)
		pkReq.Header.Set("Authorization", "Bearer "+token)
		pkReq.Header.Set("Accept", "application/vnd.github+json")
		pkReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		pkReq.Header.Set("User-Agent", "secrets-inventory-gcp")
		pkRes, err := http_.Do(pkReq)
		if err != nil {
			log.Printf("GH_PUT public-key network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if pkRes.StatusCode/100 != 2 {
			pkRes.Body.Close()
			log.Printf("GH_PUT public-key upstream %d actor=%q target=%q",
				pkRes.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		var pk ghPublicKey
		if err := json.NewDecoder(pkRes.Body).Decode(&pk); err != nil {
			pkRes.Body.Close()
			log.Printf("GH_PUT public-key decode actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		pkRes.Body.Close()

		encryptedB64, err := sealedBoxEncrypt([]byte(body.Value), pk.Key)
		if err != nil {
			log.Printf("GH_PUT sealed box encrypt actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		putBody, _ := json.Marshal(struct {
			EncryptedValue string `json:"encrypted_value"`
			KeyID          string `json:"key_id"`
			Visibility     string `json:"visibility"`
		}{EncryptedValue: encryptedB64, KeyID: pk.KeyID, Visibility: visibility})

		putURL := fmt.Sprintf("%s/orgs/%s/actions/secrets/%s", githubAPI, cfg.org, name)
		putReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, putURL,
			strings.NewReader(string(putBody)))
		putReq.Header.Set("Authorization", "Bearer "+token)
		putReq.Header.Set("Content-Type", "application/json")
		putReq.Header.Set("Accept", "application/vnd.github+json")
		putReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		putReq.Header.Set("User-Agent", "secrets-inventory-gcp")
		putRes, err := http_.Do(putReq)
		if err != nil {
			log.Printf("GH_PUT upstream network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer putRes.Body.Close()
		// GitHub PUT returns 201 Created or 204 No Content
		if putRes.StatusCode != http.StatusCreated && putRes.StatusCode != http.StatusNoContent {
			log.Printf("GH_PUT upstream %d actor=%q target=%q", putRes.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("GH_PUT ok actor=%q target=%q created=%v", actor, target, failIfExists)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ghPutResponse{Ok: true, Created: failIfExists})
	})
}

// sealedBoxEncrypt は libsodium の crypto_box_seal pattern を再現する。
// Curve25519 public key (base64) を受け取り、ephemeral key pair で sealed
// box を作って base64 で返す。Go の `golang.org/x/crypto/nacl/box` の
// `SealAnonymous` がまさにこれ (= ephemeral key + blake2b nonce)。
//
// GitHub Actions org secret は本 encrypt 方式を要求する (libsodium
// crypto_box_seal、API docs に明記)。
func sealedBoxEncrypt(plaintext []byte, recipientPublicKeyB64 string) (string, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(recipientPublicKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pkBytes) != 32 {
		return "", fmt.Errorf("invalid public key length: %d (expected 32)", len(pkBytes))
	}
	var pk [32]byte
	copy(pk[:], pkBytes)

	sealed, err := box.SealAnonymous(nil, plaintext, &pk, nil)
	if err != nil {
		return "", fmt.Errorf("seal anonymous: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
