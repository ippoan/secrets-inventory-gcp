package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestGhList_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets?per_page=100&page=1",
		200, `{"total_count":2,"secrets":[{"name":"A","created_at":"2026-01-01","updated_at":"2026-05-01","visibility":"all"},{"name":"B","created_at":"2026-02-01","updated_at":"2026-05-02","visibility":"private"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Secrets) != 2 {
		t.Errorf("len = %d", len(resp.Secrets))
	}
	if doer.calls[0].Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Errorf("missing api version header")
	}
}

func TestGhList_Unauthorized(t *testing.T) {
	mux := newGhTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestGhPut_OK_NewSecret(t *testing.T) {
	// recipient keypair を生成して proxy が正しく sealed box する経路を verify
	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(recipientPub[:])

	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		404, "")
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		200, `{"key_id":"kid-1","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		201, "")
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"plaintext-secret","visibility":"all"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/MY_SECRET", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	req.Header.Set("X-Fail-If-Exists", "true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghPutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Ok || !resp.Created {
		t.Errorf("ok=%v created=%v", resp.Ok, resp.Created)
	}
	// response に plaintext が echo されていないか
	if strings.Contains(rec.Body.String(), "plaintext-secret") {
		t.Error("response should not echo plaintext")
	}

	// PUT body の encrypted_value を取り出して、recipient secret key で decrypt
	// すると元の plaintext に戻ることを確認 (= sealed box が正しい)
	var putReq *http.Request
	for _, c := range doer.calls {
		if c.Method == http.MethodPut {
			putReq = c
			break
		}
	}
	if putReq == nil {
		t.Fatal("PUT not made")
	}
	putBody, _ := io.ReadAll(putReq.Body)
	var put struct {
		EncryptedValue string `json:"encrypted_value"`
		KeyID          string `json:"key_id"`
		Visibility     string `json:"visibility"`
	}
	if err := json.Unmarshal(putBody, &put); err != nil {
		t.Fatal(err)
	}
	if put.KeyID != "kid-1" || put.Visibility != "all" {
		t.Errorf("unexpected: %+v", put)
	}
	sealedBytes, err := base64.StdEncoding.DecodeString(put.EncryptedValue)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, sealedBytes, recipientPub, recipientPriv)
	if !ok {
		t.Fatal("could not open sealed box")
	}
	if string(opened) != "plaintext-secret" {
		t.Errorf("opened = %q", string(opened))
	}
}

func TestGhPut_ConflictWhenFailIfExists(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		200, `{"name":"MY_SECRET","created_at":"2026-01-01","updated_at":"2026-05-01"}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"v"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/MY_SECRET", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	req.Header.Set("X-Fail-If-Exists", "true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestGhPut_NoExistenceCheckByDefault(t *testing.T) {
	// fail_if_exists default = false なので existence check は呼ばれない
	recipientPub, _, _ := box.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(recipientPub[:])

	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		200, `{"key_id":"k","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/EXISTING_SECRET",
		204, "")
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"v"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/EXISTING_SECRET", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghPutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Ok || resp.Created {
		t.Errorf("expected ok=true created=false, got %+v", resp)
	}
	// GET /secrets/EXISTING_SECRET が呼ばれていないことを確認
	for _, c := range doer.calls {
		if c.Method == "GET" && strings.HasSuffix(c.URL.Path, "/EXISTING_SECRET") {
			t.Error("existence check should not be called when fail_if_exists=false")
		}
	}
}

func TestGhPut_RejectInvalidName(t *testing.T) {
	mux := newGhTestMux(&fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}, &fakeHTTPDoer{})
	body := bytes.NewBufferString(`{"value":"v"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/has%2Fslash", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestSealedBoxEncrypt_RoundTrip(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encB64, err := sealedBoxEncrypt([]byte("hello"), base64.StdEncoding.EncodeToString(pub[:]))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		t.Fatal("open failed")
	}
	if string(opened) != "hello" {
		t.Errorf("got %q", string(opened))
	}
}

func TestSealedBoxEncrypt_InvalidPublicKey(t *testing.T) {
	if _, err := sealedBoxEncrypt([]byte("x"), "not-base64!"); err == nil {
		t.Error("expected error for invalid base64")
	}
	if _, err := sealedBoxEncrypt([]byte("x"), base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for wrong-length key")
	}
}

// ---- per-request org 指定 (GH_EXTRA_ORGS allowlist、Refs #49) ----

func newGhExtraOrgTestMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
	return newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		getter,
		nil,
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{org: "ippoan", tokenSecret: "gh-token",
			extraOrgs: map[string]string{"ohishi-exp": "gh-token-ohishi-exp"}},
		doer,
		"p", "k",
	)
}

func TestParseGhExtraOrgs(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"empty", "", map[string]string{}, false},
		{"whitespace only", "   ", map[string]string{}, false},
		{"single", "ohishi-exp=gh-write-ohishi",
			map[string]string{"ohishi-exp": "gh-write-ohishi"}, false},
		{"multi with spaces", " ohishi-exp = gh-write-ohishi , foo = bar-secret ,",
			map[string]string{"ohishi-exp": "gh-write-ohishi", "foo": "bar-secret"}, false},
		{"missing equals", "ohishi-exp", nil, true},
		{"invalid org (leading hyphen)", "-bad=secret-name", nil, true},
		{"invalid org (chars)", "bad org=secret-name", nil, true},
		{"invalid secret name", "ohishi-exp=1leading-digit", nil, true},
		{"duplicate org", "a=s1,a=s2", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseGhExtraOrgs(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("got[%q]=%q want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestGhConfigResolve(t *testing.T) {
	base := ghConfig{org: "ippoan", tokenSecret: "gh-token",
		extraOrgs: map[string]string{"ohishi-exp": "gh-token-ohishi-exp"}}

	if got, err := base.resolve(""); err != nil || got.org != "ippoan" || got.tokenSecret != "gh-token" {
		t.Fatalf("empty: %+v %v", got, err)
	}
	if got, err := base.resolve("ippoan"); err != nil || got.org != "ippoan" || got.tokenSecret != "gh-token" {
		t.Fatalf("default explicit: %+v %v", got, err)
	}
	if got, err := base.resolve("ohishi-exp"); err != nil ||
		got.org != "ohishi-exp" || got.tokenSecret != "gh-token-ohishi-exp" {
		t.Fatalf("extra: %+v %v", got, err)
	}
	if _, err := base.resolve("unknown-org"); err == nil {
		t.Fatal("expected error for org outside allowlist")
	}
	// extraOrgs が nil でも default org は通る (= backward compat)。
	noExtra := ghConfig{org: "ippoan", tokenSecret: "gh-token"}
	if _, err := noExtra.resolve("ippoan"); err != nil {
		t.Fatalf("default on nil extraOrgs: %v", err)
	}
	if _, err := noExtra.resolve("ohishi-exp"); err == nil {
		t.Fatal("expected error on nil extraOrgs for non-default org")
	}
}

func TestGhList_ExtraOrg_UsesOrgSpecificToken(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets?per_page=100&page=1",
		200, `{"total_count":1,"secrets":[{"name":"CI_APP_ID","created_at":"2026-06-01","updated_at":"2026-06-01","visibility":"all"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"gh-token":            "tok-ippoan",
		"gh-token-ohishi-exp": "tok-ohishi",
	}}

	mux := newGhExtraOrgTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets?org=ohishi-exp", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := doer.calls[0].Header.Get("Authorization"); got != "Bearer tok-ohishi" {
		t.Errorf("Authorization = %q (org 専用 PAT が使われていない)", got)
	}
}

func TestGhList_OrgNotAllowed(t *testing.T) {
	mux := newGhExtraOrgTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/gh/secrets?org=unknown-org", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGhPut_ExtraOrg_OK(t *testing.T) {
	recipientPub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(recipientPub[:])

	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets/public-key",
		200, `{"key_id":"kid-9","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ohishi-exp/actions/secrets/CI_APP_ID",
		201, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"gh-token-ohishi-exp": "tok-ohishi",
	}}

	mux := newGhExtraOrgTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"12345","visibility":"all"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/CI_APP_ID?org=ohishi-exp", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, c := range doer.calls {
		if got := c.Header.Get("Authorization"); got != "Bearer tok-ohishi" {
			t.Errorf("%s %s Authorization = %q", c.Method, c.URL, got)
		}
	}
}

func TestGhPut_OrgNotAllowed(t *testing.T) {
	mux := newGhExtraOrgTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	body := bytes.NewBufferString(`{"value":"x"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/secrets/CI_APP_ID?org=unknown-org", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
