package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func genPkcs1PEM(t *testing.T) (pkcs1 []byte, pkcs8 []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pkcs1 = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkcs8 = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pkcs1, pkcs8
}

func TestConvertPkcs1ToPkcs8(t *testing.T) {
	pkcs1, _ := genPkcs1PEM(t)

	out, converted, err := convertPkcs1ToPkcs8(pkcs1)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !converted {
		t.Fatalf("expected converted=true for PKCS#1 input")
	}
	block, _ := pem.Decode(out)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("output is not PKCS#8 PRIVATE KEY PEM: %v", block)
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("output not parseable as PKCS#8: %v", err)
	}
}

func TestConvertPkcs8Idempotent(t *testing.T) {
	_, pkcs8 := genPkcs1PEM(t)
	out, converted, err := convertPkcs1ToPkcs8(pkcs8)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if converted {
		t.Fatalf("expected converted=false for already-PKCS#8 input")
	}
	if string(out) != string(pkcs8) {
		t.Fatalf("passthrough should return input unchanged")
	}
}

func TestConvertPkcs1ToPkcs8Errors(t *testing.T) {
	if _, _, err := convertPkcs1ToPkcs8([]byte("not pem")); err == nil {
		t.Fatalf("expected error for non-PEM input")
	}
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	if _, _, err := convertPkcs1ToPkcs8(other); err == nil {
		t.Fatalf("expected error for unsupported PEM type")
	}
}

// --- handler-level tests (reuse fakeLister / fakeSecretValueGetter) ---

func TestHandleConvertPkcs8_GcpOnly(t *testing.T) {
	pkcs1, _ := genPkcs1PEM(t)
	lister := &fakeLister{}
	src := &fakeSecretValueGetter{values: map[string]string{"CI_APP_PRIVATE_KEY": string(pkcs1)}}
	h := handleConvertPkcs8(lister, src, &fakeSecretValueGetter{}, ghConfig{}, nil, "proj")

	req := httptest.NewRequest(http.MethodPost,
		"/convert-pkcs8/CI_APP_PRIVATE_KEY?dst_name=CI_APP_PRIVATE_KEY_PKCS8", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp convertPkcs8Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !resp.Ok || !resp.Converted || resp.DstName != "CI_APP_PRIVATE_KEY_PKCS8" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	if resp.Results["gcp"].Status != "ok" || !resp.Results["gcp"].Created {
		t.Fatalf("gcp result: %+v", resp.Results["gcp"])
	}
	// 書き込まれた値が PKCS#8 であること。
	if len(lister.addedVersions) != 1 {
		t.Fatalf("expected 1 AddSecretVersion call, got %d", len(lister.addedVersions))
	}
	block, _ := pem.Decode(lister.addedVersions[0].value)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("written value not PKCS#8: %v", block)
	}
	// 応答 body に鍵が漏れていないこと。
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("response body leaked key material")
	}
}

func TestHandleConvertPkcs8_VersionUpWhenExists(t *testing.T) {
	pkcs1, _ := genPkcs1PEM(t)
	lister := &fakeLister{existingSecrets: map[string]bool{"DST": true}}
	src := &fakeSecretValueGetter{values: map[string]string{"SRC": string(pkcs1)}}
	h := handleConvertPkcs8(lister, src, &fakeSecretValueGetter{}, ghConfig{}, nil, "proj")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/convert-pkcs8/SRC?dst_name=DST", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp convertPkcs8Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Results["gcp"].Created {
		t.Fatalf("expected Created=false (version-up) when secret already exists")
	}
	if len(lister.addedVersions) != 1 {
		t.Fatalf("expected AddSecretVersion to still run on existing secret")
	}
}

func TestHandleConvertPkcs8_Validation(t *testing.T) {
	pkcs1, _ := genPkcs1PEM(t)
	mk := func() http.Handler {
		src := &fakeSecretValueGetter{values: map[string]string{"SRC": string(pkcs1)}}
		return handleConvertPkcs8(&fakeLister{}, src, &fakeSecretValueGetter{}, ghConfig{}, nil, "proj")
	}
	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"GET", http.MethodGet, "/convert-pkcs8/SRC?dst_name=DST", http.StatusMethodNotAllowed},
		{"missing dst", http.MethodPost, "/convert-pkcs8/SRC", http.StatusBadRequest},
		{"dst==src", http.MethodPost, "/convert-pkcs8/SRC?dst_name=SRC", http.StatusBadRequest},
		{"bad targets", http.MethodPost, "/convert-pkcs8/SRC?dst_name=DST&targets=cf", http.StatusBadRequest},
		{"gh without config", http.MethodPost, "/convert-pkcs8/SRC?dst_name=DST&targets=gcp,gh", http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mk().ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

func TestHandleConvertPkcs8_BadKeyData(t *testing.T) {
	src := &fakeSecretValueGetter{values: map[string]string{"SRC": "garbage not pem"}}
	h := handleConvertPkcs8(&fakeLister{}, src, &fakeSecretValueGetter{}, ghConfig{}, nil, "proj")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/convert-pkcs8/SRC?dst_name=DST", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
