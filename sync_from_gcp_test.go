package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func newSyncTestMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
	return newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		getter,
		nil, // srcGetter; nil → handler falls back to getter (= legacy direct-read behavior)
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{org: "ippoan", tokenSecret: "gh-token"},
		doer,
		"p", "k",
	)
}

func newSyncRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	req.Header.Set("X-Actor-Email", "alice@example.com")
	return req
}

func TestSyncFromGcp_MissingApiKey(t *testing.T) {
	mux := newSyncTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodPost, "/sync-from-gcp/MY_SECRET?targets=gh", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_WrongMethod(t *testing.T) {
	mux := newSyncTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/sync-from-gcp/MY_SECRET?targets=gh", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_ValidationErrors(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		wantCode int
	}{
		{"missing src name", "/sync-from-gcp/", http.StatusBadRequest},
		{"slash in src name", "/sync-from-gcp/A/B", http.StatusBadRequest},
		{"invalid src name", "/sync-from-gcp/123abc", http.StatusBadRequest},
		{"missing targets", "/sync-from-gcp/MY_SECRET", http.StatusBadRequest},
		{"bogus targets", "/sync-from-gcp/MY_SECRET?targets=xxx", http.StatusBadRequest},
		{"only commas", "/sync-from-gcp/MY_SECRET?targets=,,", http.StatusBadRequest},
		{"invalid gh_name", "/sync-from-gcp/MY_SECRET?targets=gh&gh_name=1abc", http.StatusBadRequest},
		{"invalid cf_name", "/sync-from-gcp/MY_SECRET?targets=cf&cf_name=1abc", http.StatusBadRequest},
		{"invalid visibility", "/sync-from-gcp/MY_SECRET?targets=gh&visibility=public", http.StatusBadRequest},
		{"invalid fail_if_exists", "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=maybe", http.StatusBadRequest},
		// repos (Refs #66)。詳細な表は TestSyncFromGcp_Repos_ValidationErrors。
		{"selected without repos", "/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected", http.StatusBadRequest},
		{"all with repos", "/sync-from-gcp/MY_SECRET?targets=gh&visibility=all&repos=repo-a", http.StatusBadRequest},
		{"invalid repo name", "/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=a/b", http.StatusBadRequest},
		{"repos without gh target", "/sync-from-gcp/MY_SECRET?targets=cf&visibility=selected&repos=repo-a", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := newSyncTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("X-Inventory-API-Key", "k")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("got %d, want %d (body=%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}

func TestSyncFromGcp_NoTargetsSelected(t *testing.T) {
	// "targets=," parses to empty list (no valid targets after splitting)
	mux := newSyncTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=,")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyncFromGcp_GhTargetButGhCfgMissing(t *testing.T) {
	mux := newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		&fakeSecretValueGetter{},
		nil, // srcGetter
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{}, // not configured
		&fakeHTTPDoer{},
		"p", "k",
	)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_CfTargetButCfCfgMissing(t *testing.T) {
	mux := newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		&fakeSecretValueGetter{},
		nil,        // srcGetter
		cfConfig{}, // not configured
		ghConfig{org: "ippoan", tokenSecret: "gh-token"},
		&fakeHTTPDoer{},
		"p", "k",
	)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=cf")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_SourceReadFails(t *testing.T) {
	getter := &fakeSecretValueGetter{err: errors.New("permission denied")}
	mux := newSyncTestMux(getter, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_EmptySourcePayload(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{"MY_SECRET": ""}}
	mux := newSyncTestMux(getter, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

// generates an ephemeral keypair, base64-encodes the pubkey, returns both
// pieces + the responded fake payload for /public-key endpoint.
func genGhPubkey(t *testing.T) (pub, priv *[32]byte, pubB64 string) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub[:])
}

func TestSyncFromGcp_Gh_Success_NewSecret_AndEncryptionRoundTrip(t *testing.T) {
	recipientPub, recipientPriv, pubB64 := genGhPubkey(t)

	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/HEALTH_OAUTH_JWT",
		http.StatusNotFound, "")
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-1","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/HEALTH_OAUTH_JWT",
		http.StatusCreated, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HEALTH_OAUTH_JWT": "the.actual.jwt.value",
		"gh-token":         "ghpat",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HEALTH_OAUTH_JWT?targets=gh")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Ok || resp.Source != "HEALTH_OAUTH_JWT" {
		t.Fatalf("bad resp: %+v", resp)
	}
	if r, ok := resp.Results["gh"]; !ok || r.Status != "ok" || !r.Created {
		t.Fatalf("gh result: %+v", r)
	}
	// Response body MUST NOT contain the plaintext value (= the JWT we synced).
	if strings.Contains(rec.Body.String(), "the.actual.jwt.value") {
		t.Fatal("response leaked plaintext")
	}

	// Verify the encrypted PUT body decrypts back to the GCP value.
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
	sealed, _ := base64.StdEncoding.DecodeString(put.EncryptedValue)
	opened, ok := box.OpenAnonymous(nil, sealed, recipientPub, recipientPriv)
	if !ok {
		t.Fatal("could not open sealed box")
	}
	if string(opened) != "the.actual.jwt.value" {
		t.Fatalf("plaintext mismatch: %q", string(opened))
	}
}

func TestSyncFromGcp_Gh_ConflictWhenExists(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusOK, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Results["gh"].Status != "fail" || !strings.Contains(resp.Results["gh"].Error, "already exists") {
		t.Fatalf("expected gh exists fail: %+v", resp.Results["gh"])
	}
}

func TestSyncFromGcp_Gh_TokenFetchFails(t *testing.T) {
	getter := &fakeSecretValueGetter{
		values: map[string]string{"MY_SECRET": "v"},
		// gh-token missing → getter returns "not found" error
	}
	mux := newSyncTestMux(getter, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyncFromGcp_Gh_PutUpstreamFails(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusInternalServerError, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Gh_PubkeyMalformed(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid","key":"not-base64-or-wrong-len"}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Gh_PubkeyUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusInternalServerError, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Gh_PubkeyDecodeError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, "not-json")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Gh_ExistenceCheckUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusInternalServerError, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

// ---- CF path ---------------------------------------------------------------

func TestSyncFromGcp_Cf_Create_NewSecret(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[]}`)
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		http.StatusOK, `{"success":true,"result":[{"id":"cf-id-1","name":"hcr-key"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY":  "the-secret-value",
		"cf-token": "cftok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key&scopes=workers")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if r, ok := resp.Results["cf"]; !ok || r.Status != "ok" || r.SecretID != "cf-id-1" || !r.Created {
		t.Fatalf("cf result: %+v", r)
	}
	if strings.Contains(rec.Body.String(), "the-secret-value") {
		t.Fatal("response leaked plaintext")
	}
}

func TestSyncFromGcp_Cf_Rotate_ExistingSecret(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[{"id":"cf-id-99","name":"hcr-key"}]}`)
	doer.respond("PATCH https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets/cf-id-99",
		http.StatusOK, `{"success":true,"result":{"id":"cf-id-99","name":"hcr-key"}}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t,
		"/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if r := resp.Results["cf"]; r.Status != "ok" || r.SecretID != "cf-id-99" || r.Created {
		t.Fatalf("cf result: %+v", r)
	}
}

func TestSyncFromGcp_Cf_ConflictWhenFailIfExists(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[{"id":"cf-id-99","name":"hcr-key"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t,
		"/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key&fail_if_exists=true")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.Results["cf"].Error, "already exists") {
		t.Fatalf("expected exists error: %+v", resp.Results["cf"])
	}
}

func TestSyncFromGcp_Cf_LookupUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusInternalServerError, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_LookupDecodeError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, "not-json")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_LookupEnvelopeSuccessFalse(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":false,"result":[]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_CreateUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[]}`)
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		http.StatusServiceUnavailable, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_CreateBadEnvelope(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[]}`)
	// 2xx but missing id in both single + array shapes → bad envelope path
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		http.StatusOK, `{"success":true,"result":[]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_PatchUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=hcr-key",
		http.StatusOK, `{"success":true,"result":[{"id":"cf-id-99","name":"hcr-key"}]}`)
	doer.respond("PATCH https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets/cf-id-99",
		http.StatusServiceUnavailable, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"HCR_KEY": "v", "cf-token": "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t,
		"/sync-from-gcp/HCR_KEY?targets=cf&cf_name=hcr-key&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestSyncFromGcp_Cf_TokenFetchFails(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{"HCR_KEY": "v"}}
	mux := newSyncTestMux(getter, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/HCR_KEY?targets=cf")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ---- combined gh+cf --------------------------------------------------------

func TestSyncFromGcp_BothTargets_Success(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusCreated, "")
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=my-secret",
		http.StatusOK, `{"success":true,"result":[]}`)
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		http.StatusOK, `{"success":true,"result":[{"id":"cf-id-2","name":"my-secret"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v",
		"cf-token":  "cftok",
		"gh-token":  "ghpat",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh,cf&cf_name=my-secret&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Ok ||
		resp.Results["gh"].Status != "ok" ||
		resp.Results["cf"].Status != "ok" {
		t.Fatalf("bad resp: %+v", resp)
	}
}

func TestSyncFromGcp_OneTargetFails_OverallNotOk(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusCreated, "")
	// CF lookup fails → cf target fails
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?name=MY_SECRET",
		http.StatusInternalServerError, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v",
		"cf-token":  "tok",
		"gh-token":  "tok",
	}}

	mux := newSyncTestMux(getter, doer)
	req := newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh,cf&fail_if_exists=false")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
	var resp syncFromGcpResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Ok {
		t.Fatal("expected ok=false")
	}
	if resp.Results["gh"].Status != "ok" {
		t.Fatalf("gh should still be ok: %+v", resp.Results["gh"])
	}
	if resp.Results["cf"].Status != "fail" {
		t.Fatalf("cf should be fail: %+v", resp.Results["cf"])
	}
}

// ---- helper ----------------------------------------------------------------

func TestParseCsvQuery(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b ,c", []string{"a", "b", "c"}},
		{",,a,,", []string{"a"}},
	}
	for _, c := range cases {
		got := parseCsvQuery(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseCsvQuery(%q): got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseCsvQuery(%q)[%d]: got %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// ---- gh_org (per-request org 指定、Refs #49) ----

func newSyncExtraOrgTestMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
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

func TestSyncFromGcp_GhOrg_NotAllowed(t *testing.T) {
	mux := newSyncExtraOrgTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/CI_APP_ID?targets=gh&gh_org=unknown-org")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyncFromGcp_GhOrg_RequiresGhTarget(t *testing.T) {
	mux := newSyncExtraOrgTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := newSyncRequest(t, "/sync-from-gcp/CI_APP_ID?targets=cf&gh_org=ohishi-exp")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyncFromGcp_GhOrg_Success_PropagatesToExtraOrg(t *testing.T) {
	recipientPub, recipientPriv, pubB64 := genGhPubkey(t)

	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets/CI_APP_PRIVATE_KEY",
		http.StatusNotFound, "")
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-2","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ohishi-exp/actions/secrets/CI_APP_PRIVATE_KEY",
		http.StatusCreated, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"CI_APP_PRIVATE_KEY_PKCS8": "-----BEGIN PRIVATE KEY-----fake",
		"gh-token-ohishi-exp":      "tok-ohishi",
	}}

	mux := newSyncExtraOrgTestMux(getter, doer)
	req := newSyncRequest(t,
		"/sync-from-gcp/CI_APP_PRIVATE_KEY_PKCS8?targets=gh&gh_org=ohishi-exp&gh_name=CI_APP_PRIVATE_KEY")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if r, ok := resp.Results["gh"]; !ok || r.Status != "ok" || !r.Created {
		t.Fatalf("gh result: %+v", r)
	}
	// org 専用 PAT が全 GitHub call で使われている (ippoan 用 PAT に
	// fallback していない) こと。
	for _, c := range doer.calls {
		if got := c.Header.Get("Authorization"); got != "Bearer tok-ohishi" {
			t.Errorf("%s %s Authorization = %q", c.Method, c.URL, got)
		}
	}
	// 値の round-trip (sealed box が ohishi-exp の鍵で開く)。
	var putBody []byte
	for _, c := range doer.calls {
		if c.Method == http.MethodPut {
			putBody, _ = io.ReadAll(c.Body)
		}
	}
	var put struct {
		EncryptedValue string `json:"encrypted_value"`
	}
	if err := json.Unmarshal(putBody, &put); err != nil {
		t.Fatal(err)
	}
	sealed, _ := base64.StdEncoding.DecodeString(put.EncryptedValue)
	opened, ok := box.OpenAnonymous(nil, sealed, recipientPub, recipientPriv)
	if !ok {
		t.Fatal("could not open sealed box")
	}
	if string(opened) != "-----BEGIN PRIVATE KEY-----fake" {
		t.Fatalf("plaintext mismatch")
	}
}

// ---- repos (visibility=selected の対象 repo、Refs #66) ----

// errOnURLDoer は URL に needle を含む request だけ network error にする。
type errOnURLDoer struct {
	inner  httpDoer
	needle string
}

func (d *errOnURLDoer) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), d.needle) {
		return nil, errors.New("simulated network error")
	}
	return d.inner.Do(req)
}

// syncPutBodies は fake doer が受けた PUT の body を順に返す。
func syncPutBodies(t *testing.T, doer *fakeHTTPDoer) [][]byte {
	t.Helper()
	var out [][]byte
	for _, c := range doer.calls {
		if c.Method == http.MethodPut {
			b, _ := io.ReadAll(c.Body)
			out = append(out, b)
		}
	}
	return out
}

func TestSyncFromGcp_Repos_ValidationErrors(t *testing.T) {
	tooMany := make([]string, 0, maxSyncRepos+1)
	for i := 0; i <= maxSyncRepos; i++ {
		tooMany = append(tooMany, "repo-"+string(rune('a'+i/26))+string(rune('a'+i%26)))
	}
	base := "/sync-from-gcp/MY_SECRET?"
	cases := []struct {
		name string
		path string
	}{
		{"selected without repos", base + "targets=gh&visibility=selected"},
		{"selected with empty repos", base + "targets=gh&visibility=selected&repos="},
		{"selected with only commas", base + "targets=gh&visibility=selected&repos=,,"},
		{"visibility omitted (all) with repos", base + "targets=gh&repos=repo-a"},
		{"all with repos", base + "targets=gh&visibility=all&repos=repo-a"},
		{"private with repos", base + "targets=gh&visibility=private&repos=repo-a"},
		{"owner-qualified name", base + "targets=gh&visibility=selected&repos=ippoan/repo-a"},
		{"name with space", base + "targets=gh&visibility=selected&repos=repo-a,bad%20name"},
		{"dot segment", base + "targets=gh&visibility=selected&repos=.."},
		{"single dot", base + "targets=gh&visibility=selected&repos=."},
		{"name too long", base + "targets=gh&visibility=selected&repos=" + strings.Repeat("a", 101)},
		{"too many repos", base + "targets=gh&visibility=selected&repos=" + strings.Join(tooMany, ",")},
		{"targets without gh", base + "targets=cf&visibility=selected&repos=repo-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := &fakeHTTPDoer{}
			getter := &fakeSecretValueGetter{values: map[string]string{
				"MY_SECRET": "v", "gh-token": "tok", "cf-token": "tok",
			}}
			mux := newSyncTestMux(getter, doer)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, newSyncRequest(t, tc.path))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			// 検証は secret を読む / GitHub を叩くより前。
			if n := getter.calls.Load(); n != 0 {
				t.Errorf("secret getter called %d times before validation", n)
			}
			if len(doer.calls) != 0 {
				t.Errorf("upstream called %d times before validation", len(doer.calls))
			}
		})
	}
}

func TestSyncFromGcp_Repos_SelectedWithoutRepos_Message(t *testing.T) {
	mux := newSyncTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected"))
	if rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "repos is required when visibility=selected") {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyncFromGcp_Repos_ExactlyMaxAccepted(t *testing.T) {
	names := make([]string, 0, maxSyncRepos)
	for i := 0; i < maxSyncRepos; i++ {
		names = append(names, "repo-"+string(rune('a'+i/26))+string(rune('a'+i%26)))
	}
	got, err := parseSyncRepos(strings.Join(names, ","))
	if err != nil || len(got) != maxSyncRepos {
		t.Fatalf("got %d names, err=%v", len(got), err)
	}
}

// targets=cf のみなら visibility=selected でも repos は要求しない
// (visibility は gh にしか効かない = 従来挙動を変えない)。
func TestSyncFromGcp_Repos_NotRequiredWithoutGhTarget(t *testing.T) {
	mux := newSyncTestMux(&fakeSecretValueGetter{err: errors.New("boom")}, &fakeHTTPDoer{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=cf&visibility=selected"))
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("got 400 body=%s", rec.Body.String())
	}
}

func TestSyncFromGcp_Repos_Selected_Success_PutsSelectedRepositoryIDs(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/repo-a",
		http.StatusOK, `{"id":101,"name":"repo-a","owner":{"login":"ippoan"}}`)
	doer.respond("GET https://api.github.com/repos/ippoan/repo.b",
		http.StatusOK, `{"id":202,"name":"repo.b","owner":{"login":"Ippoan"}}`)
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusNotFound, "")
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-1","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusCreated, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "plain-secret-value", "gh-token": "ghpat",
	}}

	mux := newSyncTestMux(getter, doer)
	// 重複 (repo-a) は 1 回だけ解決され、id も 1 個だけ載る。
	req := newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=repo-a,repo.b,repo-a")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp syncFromGcpResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if r := resp.Results["gh"]; r.Status != "ok" || r.SelectedRepositories != 2 {
		t.Fatalf("gh result: %+v", r)
	}
	if strings.Contains(rec.Body.String(), "plain-secret-value") {
		t.Fatal("response leaked plaintext")
	}

	// 解決は書き込みと同じ token で、PUT より前に行われる。
	var order []string
	for _, c := range doer.calls {
		order = append(order, c.Method+" "+c.URL.Path)
		if got := c.Header.Get("Authorization"); got != "Bearer ghpat" {
			t.Errorf("%s %s Authorization = %q", c.Method, c.URL, got)
		}
	}
	want := []string{
		"GET /repos/ippoan/repo-a",
		"GET /repos/ippoan/repo.b",
		"GET /orgs/ippoan/actions/secrets/MY_SECRET",
		"GET /orgs/ippoan/actions/secrets/public-key",
		"PUT /orgs/ippoan/actions/secrets/MY_SECRET",
	}
	if strings.Join(order, "\n") != strings.Join(want, "\n") {
		t.Fatalf("call order:\n%s\nwant:\n%s", strings.Join(order, "\n"), strings.Join(want, "\n"))
	}

	bodies := syncPutBodies(t, doer)
	if len(bodies) != 1 {
		t.Fatalf("PUT count = %d", len(bodies))
	}
	var put struct {
		Visibility            string  `json:"visibility"`
		SelectedRepositoryIDs []int64 `json:"selected_repository_ids"`
	}
	if err := json.Unmarshal(bodies[0], &put); err != nil {
		t.Fatal(err)
	}
	if put.Visibility != "selected" {
		t.Errorf("visibility = %q", put.Visibility)
	}
	if len(put.SelectedRepositoryIDs) != 2 ||
		put.SelectedRepositoryIDs[0] != 101 || put.SelectedRepositoryIDs[1] != 202 {
		t.Errorf("selected_repository_ids = %v", put.SelectedRepositoryIDs)
	}
}

// 回帰: visibility 省略 (= all) の PUT body に selected_repository_ids の key
// 自体が無い。
func TestSyncFromGcp_Repos_VisibilityAll_OmitsSelectedRepositoryIDs(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-1","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusNoContent, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, doer)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t, "/sync-from-gcp/MY_SECRET?targets=gh&fail_if_exists=false"))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "selected_repositories") {
		t.Errorf("response has selected_repositories: %s", rec.Body.String())
	}
	bodies := syncPutBodies(t, doer)
	if len(bodies) != 1 {
		t.Fatalf("PUT count = %d", len(bodies))
	}
	var put map[string]json.RawMessage
	if err := json.Unmarshal(bodies[0], &put); err != nil {
		t.Fatal(err)
	}
	if _, ok := put["selected_repository_ids"]; ok {
		t.Errorf("PUT body has selected_repository_ids: %s", bodies[0])
	}
	if string(put["visibility"]) != `"all"` {
		t.Errorf("visibility = %s", put["visibility"])
	}
	for _, c := range doer.calls {
		if strings.HasPrefix(c.URL.Path, "/repos/") {
			t.Errorf("unexpected repo lookup: %s", c.URL)
		}
	}
}

// 解決に 1 つでも失敗したら、source secret を読まず GitHub にも書かない。
func TestSyncFromGcp_Repos_ResolveFailures_NoWrite(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode int
		wantBody string
	}{
		{"404", http.StatusNotFound, `{"message":"Not Found"}`,
			http.StatusBadRequest, "repo not found or not accessible: repo-b"},
		{"403", http.StatusForbidden, "", http.StatusBadGateway, "upstream error"},
		{"500", http.StatusInternalServerError, "", http.StatusBadGateway, "upstream error"},
		{"bad json", http.StatusOK, `not-json`, http.StatusBadGateway, "upstream error"},
		{"missing id", http.StatusOK, `{"owner":{"login":"ippoan"}}`,
			http.StatusBadGateway, "upstream error"},
		// rename / transfer の redirect で別 owner の repo が返った場合。
		{"owner mismatch", http.StatusOK, `{"id":999,"owner":{"login":"other-org"}}`,
			http.StatusBadRequest, "repo not found or not accessible: repo-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := &fakeHTTPDoer{}
			doer.respond("GET https://api.github.com/repos/ippoan/repo-a",
				http.StatusOK, `{"id":101,"owner":{"login":"ippoan"}}`)
			doer.respond("GET https://api.github.com/repos/ippoan/repo-b", tc.status, tc.body)
			getter := &fakeSecretValueGetter{values: map[string]string{
				"MY_SECRET": "v", "gh-token": "tok",
			}}
			mux := newSyncTestMux(getter, doer)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, newSyncRequest(t,
				"/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=repo-a,repo-b"))
			if rec.Code != tc.wantCode || !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
			}
			for _, c := range doer.calls {
				if c.Method != http.MethodGet || !strings.HasPrefix(c.URL.Path, "/repos/ippoan/") {
					t.Errorf("unexpected upstream call: %s %s", c.Method, c.URL)
				}
			}
			// token の 1 回だけ。source secret (MY_SECRET) は読まれていない。
			if n := getter.calls.Load(); n != 1 {
				t.Errorf("secret getter calls = %d, want 1 (token only)", n)
			}
		})
	}
}

func TestSyncFromGcp_Repos_ResolveNetworkError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token": "tok",
	}}
	mux := newSyncTestMux(getter, &errOnURLDoer{inner: doer, needle: "/repos/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=repo-a"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(doer.calls) != 0 {
		t.Errorf("upstream called %d times after resolve failure", len(doer.calls))
	}
}

func TestSyncFromGcp_Repos_ResolveTokenFetchFails(t *testing.T) {
	doer := &fakeHTTPDoer{}
	// gh-token が無い → token 取得で失敗。
	getter := &fakeSecretValueGetter{values: map[string]string{"MY_SECRET": "v"}}
	mux := newSyncTestMux(getter, doer)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=repo-a"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(doer.calls) != 0 {
		t.Errorf("upstream called %d times", len(doer.calls))
	}
}

// gh_org 指定時は、解決の URL の org も token もその org のものになる。
func TestSyncFromGcp_Repos_GhOrg_ResolvesInThatOrg(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ohishi-exp/repo-a",
		http.StatusOK, `{"id":303,"owner":{"login":"ohishi-exp"}}`)
	doer.respond("GET https://api.github.com/orgs/ohishi-exp/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-2","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ohishi-exp/actions/secrets/MY_SECRET",
		http.StatusNoContent, "")
	getter := &fakeSecretValueGetter{values: map[string]string{
		"MY_SECRET": "v", "gh-token-ohishi-exp": "tok-ohishi",
	}}
	mux := newSyncExtraOrgTestMux(getter, doer)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh&gh_org=ohishi-exp&visibility=selected&repos=repo-a&fail_if_exists=false"))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(doer.calls) == 0 || doer.calls[0].URL.Path != "/repos/ohishi-exp/repo-a" {
		t.Fatalf("first call = %v", doer.calls)
	}
	for _, c := range doer.calls {
		if strings.Contains(c.URL.Path, "/ippoan/") {
			t.Errorf("call went to default org: %s", c.URL)
		}
		if got := c.Header.Get("Authorization"); got != "Bearer tok-ohishi" {
			t.Errorf("%s %s Authorization = %q", c.Method, c.URL, got)
		}
	}
	bodies := syncPutBodies(t, doer)
	if len(bodies) != 1 {
		t.Fatalf("PUT count = %d", len(bodies))
	}
	var put struct {
		SelectedRepositoryIDs []int64 `json:"selected_repository_ids"`
	}
	if err := json.Unmarshal(bodies[0], &put); err != nil {
		t.Fatal(err)
	}
	if len(put.SelectedRepositoryIDs) != 1 || put.SelectedRepositoryIDs[0] != 303 {
		t.Errorf("selected_repository_ids = %v", put.SelectedRepositoryIDs)
	}
}

// App mode では repo の解決も installation token (App JWT ではない) で行う。
func TestSyncFromGcp_Repos_AppMode_UsesInstallationToken(t *testing.T) {
	_, _, pubB64 := genGhPubkey(t)
	getter := appModeGetter(t)
	getter.values["MY_SECRET"] = "v"
	doer := appModeDoerForOrg("ippoan", "ghs_tok")
	doer.respond("GET https://api.github.com/repos/ippoan/repo-a",
		http.StatusOK, `{"id":404,"owner":{"login":"ippoan"}}`)
	doer.respond("GET https://api.github.com/orgs/ippoan/actions/secrets/public-key",
		http.StatusOK, `{"key_id":"kid-3","key":"`+pubB64+`"}`)
	doer.respond("PUT https://api.github.com/orgs/ippoan/actions/secrets/MY_SECRET",
		http.StatusNoContent, "")
	mux := newGhAppModeMux(getter, doer)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, newSyncRequest(t,
		"/sync-from-gcp/MY_SECRET?targets=gh&visibility=selected&repos=repo-a&fail_if_exists=false"))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	seen := false
	for _, c := range doer.calls {
		if c.URL.Path == "/repos/ippoan/repo-a" {
			seen = true
			if got := c.Header.Get("Authorization"); got != "Bearer ghs_tok" {
				t.Errorf("repo lookup Authorization = %q", got)
			}
		}
	}
	if !seen {
		t.Fatal("repo lookup not made")
	}
}

func TestParseSyncRepos(t *testing.T) {
	got, err := parseSyncRepos(" repo-a , repo_b,,repo-a,Repo.C ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "repo-a|repo_b|Repo.C" {
		t.Errorf("got %v", got)
	}
	if got, err := parseSyncRepos(""); err != nil || len(got) != 0 {
		t.Errorf("empty: got %v err=%v", got, err)
	}
	for _, bad := range []string{"a/b", "a b", ".", "..", "a?b", strings.Repeat("x", 101)} {
		if _, err := parseSyncRepos(bad); err == nil {
			t.Errorf("parseSyncRepos(%q): want error", bad)
		}
	}
}
