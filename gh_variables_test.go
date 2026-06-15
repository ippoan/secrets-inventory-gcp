package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGhVarList_OK(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables?per_page=100&page=1",
		200, `{"total_count":2,"variables":[{"name":"STAGING_DEPLOY_ENABLED","value":"true","created_at":"2026-01-01","updated_at":"2026-05-01"},{"name":"GCP_REGION","value":"asia-northeast1","created_at":"2026-02-01","updated_at":"2026-05-02"}]}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/gh/variables?repo=ippoan/rust-flickr", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghVariablesListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Variables) != 2 {
		t.Fatalf("len = %d", len(resp.Variables))
	}
	if resp.Variables[0].Name != "STAGING_DEPLOY_ENABLED" || resp.Variables[0].Value != "true" {
		t.Errorf("unexpected: %+v", resp.Variables[0])
	}
	if doer.calls[0].Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
		t.Errorf("missing api version header")
	}
	if got := doer.calls[0].Header.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("auth header = %q", got)
	}
}

func TestGhVarList_Unauthorized(t *testing.T) {
	mux := newGhTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodGet, "/gh/variables?repo=ippoan/rust-flickr", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestGhVarList_BadRepo(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	for _, repo := range []string{"", "noslash", "ippoan/", "/name", "ippoan/bad name"} {
		mux := newGhTestMux(getter, &fakeHTTPDoer{})
		req := httptest.NewRequest(http.MethodGet, "/gh/variables?repo="+url.QueryEscape(repo), nil)
		req.Header.Set("X-Inventory-API-Key", "k")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("repo=%q: expected 400, got %d", repo, rec.Code)
		}
	}
}

func TestGhVarList_MethodNotAllowed(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	mux := newGhTestMux(getter, &fakeHTTPDoer{})
	// POST に /gh/variables (no trailing slash) は list handler に届く
	req := httptest.NewRequest(http.MethodPost, "/gh/variables?repo=ippoan/rust-flickr", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestGhVarList_UpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables?per_page=100&page=1",
		403, `{"message":"Resource not accessible by integration"}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	mux := newGhTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodGet, "/gh/variables?repo=ippoan/rust-flickr", nil)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestGhVarPut_Create(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables/STAGING_DEPLOY_ENABLED",
		404, "")
	doer.respond("POST https://api.github.com/repos/ippoan/rust-flickr/actions/variables",
		201, "")
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"true"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/variables/STAGING_DEPLOY_ENABLED?repo=ippoan/rust-flickr", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	req.Header.Set("X-Actor-Email", "ops@example.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghVarPutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Ok || !resp.Created {
		t.Errorf("ok=%v created=%v (want created=true)", resp.Ok, resp.Created)
	}
}

func TestGhVarPut_Update(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables/STAGING_DEPLOY_ENABLED",
		200, `{"name":"STAGING_DEPLOY_ENABLED","value":"false","created_at":"2026-01-01","updated_at":"2026-05-01"}`)
	doer.respond("PATCH https://api.github.com/repos/ippoan/rust-flickr/actions/variables/STAGING_DEPLOY_ENABLED",
		204, "")
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}

	mux := newGhTestMux(getter, doer)
	body := bytes.NewBufferString(`{"value":"true"}`)
	req := httptest.NewRequest(http.MethodPut, "/gh/variables/STAGING_DEPLOY_ENABLED?repo=ippoan/rust-flickr", body)
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ghVarPutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Ok || resp.Created {
		t.Errorf("ok=%v created=%v (want created=false)", resp.Ok, resp.Created)
	}
}

func TestGhVarPut_BadInputs(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		want   int
	}{
		{"method not allowed", http.MethodPost, "/gh/variables/FOO?repo=ippoan/rust-flickr", `{"value":"x"}`, http.StatusMethodNotAllowed},
		{"missing name", http.MethodPut, "/gh/variables/?repo=ippoan/rust-flickr", `{"value":"x"}`, http.StatusBadRequest},
		{"invalid name", http.MethodPut, "/gh/variables/1bad?repo=ippoan/rust-flickr", `{"value":"x"}`, http.StatusBadRequest},
		{"bad repo", http.MethodPut, "/gh/variables/FOO?repo=noslash", `{"value":"x"}`, http.StatusBadRequest},
		{"bad json", http.MethodPut, "/gh/variables/FOO?repo=ippoan/rust-flickr", `not-json`, http.StatusBadRequest},
		{"empty value", http.MethodPut, "/gh/variables/FOO?repo=ippoan/rust-flickr", `{"value":""}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		mux := newGhTestMux(getter, &fakeHTTPDoer{})
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("X-Inventory-API-Key", "k")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: want %d got %d (body=%s)", c.name, c.want, rec.Code, rec.Body.String())
		}
	}
}

func TestGhVarPut_ExistenceCheckUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables/FOO",
		500, "")
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	mux := newGhTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodPut, "/gh/variables/FOO?repo=ippoan/rust-flickr",
		strings.NewReader(`{"value":"x"}`))
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestGhVarPut_WriteUpstreamError(t *testing.T) {
	doer := &fakeHTTPDoer{}
	doer.respond("GET https://api.github.com/repos/ippoan/rust-flickr/actions/variables/FOO",
		404, "")
	doer.respond("POST https://api.github.com/repos/ippoan/rust-flickr/actions/variables",
		422, `{"message":"Validation Failed"}`)
	getter := &fakeSecretValueGetter{values: map[string]string{"gh-token": "tok"}}
	mux := newGhTestMux(getter, doer)
	req := httptest.NewRequest(http.MethodPut, "/gh/variables/FOO?repo=ippoan/rust-flickr",
		strings.NewReader(`{"value":"x"}`))
	req.Header.Set("X-Inventory-API-Key", "k")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestGhVarPut_Unauthorized(t *testing.T) {
	mux := newGhTestMux(&fakeSecretValueGetter{}, &fakeHTTPDoer{})
	req := httptest.NewRequest(http.MethodPut, "/gh/variables/FOO?repo=ippoan/rust-flickr",
		strings.NewReader(`{"value":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
