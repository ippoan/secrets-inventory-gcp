package main

// GitHub App installation token mode (Refs #51)。
//
// per-org PAT (`GH_EXTRA_ORGS`、#49) の代わりに、GitHub App (`ippoan-ci-bot`)
// の installation access token で org secrets API を叩く。App 秘密鍵は GCP
// Secret Manager に保管済み (`CI_APP_PRIVATE_KEY` / `_PKCS8`) なので、org を
// 増やすときに新規 credential が一切要らない (= App を org に install する
// だけ)。token は 1h 短命で proxy 内に cache する。
//
// flow:
//  1. App JWT を mint (RS256、iat=-60s / exp=+9min、iss=App ID)
//  2. `GET /orgs/{org}/installation` (app JWT) → installation id
//  3. `POST /app/installations/{id}/access_tokens` (app JWT) → token
//  4. org 別に expires_at - 5min まで cache
//
// 書込可能な org の境界は **App の installation 集合そのもの** (install されて
// いない org は step 2 が 404)。App 側の Organization permissions → Secrets:
// Read and write が無いと step 3 までは成功し、secrets API が 403
// ("Resource not accessible by integration") になる — log で判別できる。

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ghAppConfig は App auth mode の設定。2 つの Secret Manager secret 名
// (App ID / RSA 秘密鍵 PEM) が両方 non-empty なら App mode 有効。
type ghAppConfig struct {
	appIDSecret string
	keySecret   string
}

func (c ghAppConfig) configured() bool {
	return c.appIDSecret != "" && c.keySecret != ""
}

type ghAppCachedToken struct {
	token     string
	expiresAt time.Time
}

// ghAppTokenCache は org → installation token の cache。ghConfig は値 copy で
// 引き回されるため pointer で共有する。
type ghAppTokenCache struct {
	mu     sync.Mutex
	tokens map[string]ghAppCachedToken
	now    func() time.Time // test 注入点
}

func newGhAppTokenCache() *ghAppTokenCache {
	return &ghAppTokenCache{tokens: map[string]ghAppCachedToken{}, now: time.Now}
}

// parseRSAPrivateKeyPEM は PKCS#1 (GitHub が download させる原本) と PKCS#8
// (`CI_APP_PRIVATE_KEY_PKCS8` = WebCrypto 用変換版) の両形式を受ける。
func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key (tried PKCS#1 and PKCS#8): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not RSA")
	}
	return rsaKey, nil
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// mintGhAppJWT は GitHub App 認証用の短命 JWT (RS256) を作る。
// clock skew 対策で iat を 60s 過去に、exp は GitHub 上限 (10min) 未満の
// 9min 先にする。
func mintGhAppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	signingInput := header + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign app jwt: %w", err)
	}
	return signingInput + "." + b64url(sig), nil
}

func ghAppAPIRequest(ctx context.Context, method, url, bearer string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "secrets-inventory-gcp")
	return req, nil
}

// tokenForOrg は org 用の installation access token を返す (cache 越し)。
// 失敗詳細は log のみ (呼び元は固定文言で 502 にラップする方針を維持)。
func (c *ghAppTokenCache) tokenForOrg(
	ctx context.Context,
	org string,
	app ghAppConfig,
	getter secretValueGetter,
	http_ httpDoer,
) (string, error) {
	c.mu.Lock()
	if cached, ok := c.tokens[org]; ok && c.now().Before(cached.expiresAt) {
		c.mu.Unlock()
		return cached.token, nil
	}
	c.mu.Unlock()

	appID, err := getter.Get(ctx, app.appIDSecret)
	if err != nil {
		return "", fmt.Errorf("app id fetch: %w", err)
	}
	appID = strings.TrimSpace(appID)
	keyPEM, err := getter.Get(ctx, app.keySecret)
	if err != nil {
		return "", fmt.Errorf("app key fetch: %w", err)
	}
	key, err := parseRSAPrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("app key parse: %w", err)
	}
	appJWT, err := mintGhAppJWT(appID, key, c.now())
	if err != nil {
		return "", err
	}

	// installation id lookup — install されていない org はここで 404 になる
	// (= installation 集合が実質の org allowlist)。
	instURL := fmt.Sprintf("%s/orgs/%s/installation", githubAPI, org)
	instReq, err := ghAppAPIRequest(ctx, http.MethodGet, instURL, appJWT)
	if err != nil {
		return "", err
	}
	instRes, err := http_.Do(instReq)
	if err != nil {
		return "", fmt.Errorf("installation lookup network: %w", err)
	}
	if instRes.StatusCode/100 != 2 {
		instRes.Body.Close()
		return "", fmt.Errorf("installation lookup upstream %d (app not installed on org?)", instRes.StatusCode)
	}
	var inst struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(instRes.Body).Decode(&inst); err != nil {
		instRes.Body.Close()
		return "", fmt.Errorf("installation lookup decode: %w", err)
	}
	instRes.Body.Close()
	if inst.ID == 0 {
		return "", fmt.Errorf("installation lookup returned id=0")
	}

	tokURL := fmt.Sprintf("%s/app/installations/%d/access_tokens", githubAPI, inst.ID)
	tokReq, err := ghAppAPIRequest(ctx, http.MethodPost, tokURL, appJWT)
	if err != nil {
		return "", err
	}
	tokRes, err := http_.Do(tokReq)
	if err != nil {
		return "", fmt.Errorf("access token mint network: %w", err)
	}
	if tokRes.StatusCode/100 != 2 {
		tokRes.Body.Close()
		return "", fmt.Errorf("access token mint upstream %d", tokRes.StatusCode)
	}
	var tok struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(tokRes.Body).Decode(&tok); err != nil {
		tokRes.Body.Close()
		return "", fmt.Errorf("access token decode: %w", err)
	}
	tokRes.Body.Close()
	if tok.Token == "" {
		return "", fmt.Errorf("access token empty")
	}

	expiresAt := tok.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = c.now().Add(55 * time.Minute)
	}
	// 期限 5 分前に失効扱いして mint し直す。
	expiresAt = expiresAt.Add(-5 * time.Minute)

	c.mu.Lock()
	c.tokens[org] = ghAppCachedToken{token: tok.Token, expiresAt: expiresAt}
	c.mu.Unlock()

	log.Printf("GH_APP token minted org=%q installation=%d", sanitizeLogValue(org), inst.ID)
	return tok.Token, nil
}
