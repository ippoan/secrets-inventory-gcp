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
