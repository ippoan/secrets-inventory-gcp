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
