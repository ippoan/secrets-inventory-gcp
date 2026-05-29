package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newCfTestMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
	return newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		getter,
		nil, // srcGetter (legacy test path → falls back to valueGetter)
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{org: "ippoan", tokenSecret: "gh-token"},
		doer,
		"p", "k",
	)
}

func newGhTestMux(getter secretValueGetter, doer httpDoer) *http.ServeMux {
	return newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		getter,
		nil, // srcGetter (legacy test path → falls back to valueGetter)
		cfConfig{accountID: "acc", storeID: "store", tokenSecret: "cf-token"},
		ghConfig{org: "ippoan", tokenSecret: "gh-token"},
		doer,
		"p", "k",
	)
}

func TestCfList_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?per_page=100",
		200, `{"success":true,"result":[{"id":"id-1","name":"FOO","scopes":["workers"],"status":"active","created":"2026-01-01T00:00:00Z","modified":"2026-05-01T00:00:00Z"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/cf/secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp cfListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Secrets) != 1 || resp.Secrets[0].Name != "FOO" || resp.Secrets[0].ID != "id-1" {
		t.Errorf("unexpected: %+v", resp.Secrets)
	}
	// upstream req に Authorization Bearer が乗っているか
	if got := doer.calls[0].Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("auth header = %q", got)
	}
}

func TestCfList_Unauthorized(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/cf/secrets", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCfList_UpstreamFailure(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets?per_page=100",
		500, "internal")
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/cf/secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestCfRotate_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("PATCH https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets/id-1",
		200, `{"success":true,"result":{"id":"id-1"}}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"new-val"}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets/id-1", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// PATCH body に value が乗っているか + log/response に echo されていないか
	patched := doer.calls[0]
	patchedBody, _ := io.ReadAll(patched.Body)
	if !strings.Contains(string(patchedBody), `"new-val"`) {
		t.Errorf("PATCH body missing value: %s", patchedBody)
	}
	if strings.Contains(rec.Body.String(), "new-val") {
		t.Error("response body should not echo the value")
	}
}

func TestCfRotate_RejectInvalidID(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	body := bytes.NewBufferString(`{"value":"x"}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets/has%2Fslash", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCfRotate_MissingValue(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}, &fakeHTTPDoer{})
	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets/id-1", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestCfCreate_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		200, `{"success":true,"result":{"id":"new-id","name":"NEW_SECRET"}}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	body := bytes.NewBufferString(`{"name":"NEW_SECRET","value":"v"}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp cfCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SecretID != "new-id" || resp.Name != "NEW_SECRET" {
		t.Errorf("unexpected: %+v", resp)
	}
	// CF API は result が配列 (1 要素) で返ることもあるので両 shape を decode できる
	if !strings.Contains(rec.Body.String(), `"NEW_SECRET"`) {
		t.Errorf("response missing name")
	}
}

func TestCfCreate_ArrayResultShape(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		200, `{"success":true,"result":[{"id":"arr-id","name":"X"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	body := bytes.NewBufferString(`{"name":"X","value":"v"}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// CF Secrets Store API は POST body を `[{...}]` 形式の array で期待する仕様。
// proxy がうっかり単体 object を送ると 400 になる (Refs #31)。assert で固定化。
func TestCfCreate_PostsArrayBody(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("POST https://api.cloudflare.com/client/v4/accounts/acc/secrets_store/stores/store/secrets",
		200, `{"success":true,"result":[{"id":"arr-id","name":"X"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	body := bytes.NewBufferString(`{"name":"X","value":"v","scopes":["workers"]}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(doer.calls) == 0 {
		t.Fatal("no upstream call captured")
	}
	raw, err := io.ReadAll(doer.calls[0].Body)
	if err != nil {
		t.Fatalf("read upstream body: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("upstream body is not a JSON array: %v\nbody=%s", err, raw)
	}
	if len(arr) != 1 {
		t.Fatalf("expected single-element array, got %d", len(arr))
	}
	if arr[0]["name"] != "X" || arr[0]["value"] != "v" {
		t.Errorf("unexpected fields: %+v", arr[0])
	}
	if scopes, _ := arr[0]["scopes"].([]any); len(scopes) != 1 || scopes[0] != "workers" {
		t.Errorf("unexpected scopes: %+v", arr[0]["scopes"])
	}
}

func TestCf_NotConfigured_Returns503(t *testing.T) {
	// cfCfg がすべて空 → 503 (= 運用 setup と code deploy を分離する degrade)
	mux := newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		&fakeSecretValueGetter{},
		nil,        // srcGetter
		cfConfig{}, // 未設定
		ghConfig{org: "ippoan", tokenSecret: "gh-token"},
		&fakeHTTPDoer{},
		"p", "k",
	)
	for _, path := range []string{"/cf/secrets", "/cf/secrets/some-id"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Inventory-API-Key", "k")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("path=%s expected 503, got %d body=%s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not configured") {
			t.Errorf("path=%s expected 'not configured' message", path)
		}
	}
}

func TestGh_NotConfigured_Returns503(t *testing.T) {
	mux := newMuxWith(
		&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{},
		&fakeSecretValueGetter{},
		nil, // srcGetter
		cfConfig{accountID: "a", storeID: "s", tokenSecret: "t"},
		ghConfig{}, // 未設定
		&fakeHTTPDoer{},
		"p", "k",
	)
	for _, path := range []string{"/gh/secrets", "/gh/secrets/SOMETHING"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Inventory-API-Key", "k")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("path=%s expected 503, got %d", path, rec.Code)
		}
	}
}

func TestCfServiceTokenList_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/access/service_tokens?per_page=100",
		200, `{"success":true,"result":[{"id":"st-1","name":"testone","client_id":"abc.access","duration":"8760h","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-05-01T00:00:00Z"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/cf/service-tokens", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp cfServiceTokenListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ServiceTokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(resp.ServiceTokens))
	}
	st := resp.ServiceTokens[0]
	if st.ID != "st-1" || st.Name != "testone" || st.ClientID != "abc.access" {
		t.Errorf("unexpected token: %+v", st)
	}
	// CF の created_at / updated_at が created / modified に正規化されているか
	if st.Created != "2026-01-01T00:00:00Z" || st.Modified != "2026-05-01T00:00:00Z" {
		t.Errorf("timestamps not normalized: %+v", st)
	}
	// upstream に Authorization Bearer が乗っているか
	if got := doer.calls[0].Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("auth header = %q", got)
	}
	// client_secret は list では返らない (= 値非漏洩) — response に出ていないこと
	if strings.Contains(rec.Body.String(), "client_secret") {
		t.Error("response must not contain client_secret")
	}
}

func TestCfServiceTokenList_Unauthorized(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/cf/service-tokens", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestCfServiceTokenList_EnvelopeFailure(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.cloudflare.com/client/v4/accounts/acc/access/service_tokens?per_page=100",
		200, `{"success":false,"errors":[{"code":1001,"message":"boom"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}

	mux := newCfTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/cf/service-tokens", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestCfServiceTokenList_TokenFetchFailure(t *testing.T) {
	// getter に cf-token が無い → token fetch 失敗 → 502
	mux := newCfTestMux(&fakeSecretValueGetter{values: map[string]string{}}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/cf/service-tokens", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestCfServiceTokenList_MethodNotAllowed(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodPost, "/cf/service-tokens", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestCfCreate_RejectInvalidName(t *testing.T) {
	mux := newCfTestMux(&fakeSecretValueGetter{values: map[string]string{"cf-token": "tok"}}, &fakeHTTPDoer{})
	body := bytes.NewBufferString(`{"name":"has spaces","value":"v"}`)
	req := httptest.NewRequest(http.MethodPost, "/cf/secrets", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}
