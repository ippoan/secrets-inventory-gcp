package main

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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// genAppKeyPEM はテスト用 RSA 鍵を生成し PKCS#1 / PKCS#8 の PEM を返す。
func genAppKeyPEM(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	return key, string(pkcs1), string(pkcs8)
}

func TestParseRSAPrivateKeyPEM_BothFormats(t *testing.T) {
	_, pkcs1, pkcs8 := genAppKeyPEM(t)
	if _, err := parseRSAPrivateKeyPEM([]byte(pkcs1)); err != nil {
		t.Fatalf("PKCS#1: %v", err)
	}
	if _, err := parseRSAPrivateKeyPEM([]byte(pkcs8)); err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}
	if _, err := parseRSAPrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestMintGhAppJWT_SignatureAndClaims(t *testing.T) {
	key, _, _ := genAppKeyPEM(t)
	now := time.Unix(1_750_000_000, 0)
	jwt, err := mintGhAppJWT("12345", key, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt shape: %d parts", len(parts))
	}
	// 署名検証 (RS256)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature verify: %v", err)
	}
	// claims (iat 60s 過去 / exp 9min 先 / iss = app id)
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "12345" {
		t.Errorf("iss = %q", claims.Iss)
	}
	if claims.Iat != now.Unix()-60 {
		t.Errorf("iat = %d", claims.Iat)
	}
	if claims.Exp != now.Add(9*time.Minute).Unix() {
		t.Errorf("exp = %d", claims.Exp)
	}
	if claims.Exp-claims.Iat >= 600+60 {
		t.Errorf("jwt lifetime exceeds GitHub 10min cap")
	}
}

func appModeGetter(t *testing.T) *fakeSecretValueGetter {
	t.Helper()
	_, pkcs1, _ := genAppKeyPEM(t)
	return &fakeSecretValueGetter{values: map[string]string{
		"CI_APP_ID":          "12345\n", // trailing newline 混入も TrimSpace で許容
		"CI_APP_PRIVATE_KEY": pkcs1,
	}}
}

func appModeDoerForOrg(org, token string) *fakeHTTPDoer {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/"+org+"/installation",
		200, `{"id":777}`)
	doer.respond("POST https://api.github.com/app/installations/777/access_tokens",
		201, `{"token":"`+token+`","expires_at":"2099-01-01T00:00:00Z"}`)
	return doer
}

func TestGhAppTokenCache_MintAndCache(t *testing.T) {
	getter := appModeGetter(t)
	doer := appModeDoerForOrg("ohishi-exp", "ghs_inst_token")
	app := ghAppConfig{appIDSecret: "CI_APP_ID", keySecret: "CI_APP_PRIVATE_KEY"}
	cache := newGhAppTokenCache()

	tok, err := cache.tokenForOrg(context.Background(), "ohishi-exp", app, getter, doer)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "ghs_inst_token" {
		t.Fatalf("token = %q", tok)
	}
	calls := len(doer.calls)

	// 2 回目は cache hit (= GitHub API への追加 call なし)。
	tok2, err := cache.tokenForOrg(context.Background(), "ohishi-exp", app, getter, doer)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != "ghs_inst_token" || len(doer.calls) != calls {
		t.Fatalf("expected cache hit, calls %d -> %d", calls, len(doer.calls))
	}

	// installation lookup には app JWT (3-part) が使われていること。
	auth := doer.calls[0].Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || strings.Count(auth, ".") != 2 {
		t.Errorf("installation lookup auth = %q (app JWT expected)", auth)
	}
}

func TestGhAppTokenCache_NotInstalledOrg(t *testing.T) {
	getter := appModeGetter(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/no-install/installation", 404, `{}`)
	app := ghAppConfig{appIDSecret: "CI_APP_ID", keySecret: "CI_APP_PRIVATE_KEY"}

	_, err := newGhAppTokenCache().tokenForOrg(context.Background(), "no-install", app, getter, doer)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected installation 404 error, got %v", err)
	}
}

func newGhAppModeMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
	return newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		getter,
		nil,
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{org: "ippoan",
			app:      ghAppConfig{appIDSecret: "CI_APP_ID", keySecret: "CI_APP_PRIVATE_KEY"},
			appCache: newGhAppTokenCache()},
		doer,
		"p", "k",
	)
}

func TestGhList_AppMode_ArbitraryInstalledOrg(t *testing.T) {
	getter := appModeGetter(t)
	doer := appModeDoerForOrg("ohishi-exp", "ghs_tok")
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets?per_page=100&page=1",
		200, `{"total_count":0,"secrets":[]}`)

	mux := newGhAppModeMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets?org=ohishi-exp", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// secrets list call は installation token を使う (app JWT ではない)。
	last := doer.calls[len(doer.calls)-1]
	if got := last.Header.Get("Authorization"); got != "Bearer ghs_tok" {
		t.Errorf("secrets list auth = %q", got)
	}
}

func TestGhList_AppMode_InvalidOrgPattern(t *testing.T) {
	mux := newGhAppModeMux(appModeGetter(t), &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets?org=-bad-", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGhConfig_ConfiguredWithAppOnly(t *testing.T) {
	c := ghConfig{org: "ippoan",
		app: ghAppConfig{appIDSecret: "CI_APP_ID", keySecret: "CI_APP_PRIVATE_KEY"}}
	if !c.configured() {
		t.Fatal("app-only config should be configured")
	}
	if (ghConfig{org: "ippoan"}).configured() {
		t.Fatal("org-only config should NOT be configured")
	}
}
