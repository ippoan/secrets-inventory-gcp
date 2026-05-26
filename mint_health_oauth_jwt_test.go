package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const fakeJwtSecret = "test-jwt-secret-32chars-padding!"

func newMintRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mint-health-oauth-jwt", nil)
	req.Header.Set("X-Actor-Email", "alice@example.com")
	return req
}

// fixedNow returns a deterministic clock for tests.
func fixedNow() time.Time {
	return time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
}

func verifyAndDecodeJwt(t *testing.T, token, secret string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d (%q)", len(parts), token)
	}
	enc := base64.RawURLEncoding
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(parts[0] + "." + parts[1])); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	wantSig := enc.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(wantSig)) {
		t.Fatalf("signature mismatch")
	}
	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]string
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr["alg"] != "HS256" || hdr["typ"] != "JWT" {
		t.Fatalf("unexpected header: %v", hdr)
	}
	claimsBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestMintHealthOAuthJwt_HappyPath(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, body=%q", rr.Code, rr.Body.String())
	}
	var resp mintHealthOAuthJwtResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%q", err, rr.Body.String())
	}
	if !resp.Ok || resp.SecretName != mintOutputSecretName ||
		!resp.Created || !strings.HasSuffix(resp.NewVersion, "/versions/MOCK") {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	// Response body MUST NOT contain the actual JWT value.
	if bytes.Contains(rr.Body.Bytes(), []byte(fakeJwtSecret)) {
		t.Fatalf("response body contains JWT_SECRET (must not echo)")
	}

	// Expected: 1 CreateSecret call + 1 AddSecretVersion call.
	if len(lister.createCalls) != 1 || lister.createCalls[0].shortName != mintOutputSecretName {
		t.Fatalf("create calls: %+v", lister.createCalls)
	}
	if len(lister.addedVersions) != 1 {
		t.Fatalf("expected 1 AddSecretVersion call, got %d", len(lister.addedVersions))
	}
	if !strings.HasSuffix(lister.addedVersions[0].secretName,
		"/secrets/"+mintOutputSecretName) {
		t.Fatalf("AddSecretVersion called on wrong secret: %q",
			lister.addedVersions[0].secretName)
	}

	// Verify the JWT that was uploaded.
	uploaded := string(lister.addedVersions[0].value)
	claims := verifyAndDecodeJwt(t, uploaded, fakeJwtSecret)
	if claims["sub"] != mintJwtSub {
		t.Fatalf("sub: got %v", claims["sub"])
	}
	iat, ok := claims["iat"].(float64)
	if !ok || int64(iat) != fixedNow().Unix() {
		t.Fatalf("iat: got %v", claims["iat"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) != fixedNow().Add(mintJwtTtl).Unix() {
		t.Fatalf("exp: got %v", claims["exp"])
	}

	// expires_at field in response should be parseable RFC3339 and match exp.
	parsed, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse ExpiresAt: %v", err)
	}
	if parsed.Unix() != int64(exp) {
		t.Fatalf("ExpiresAt %v doesn't match exp claim %v", parsed.Unix(), int64(exp))
	}
}

func TestMintHealthOAuthJwt_ExistingSecret_AddsVersion(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{
		existingSecrets: map[string]bool{mintOutputSecretName: true},
	}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	var resp mintHealthOAuthJwtResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Created {
		t.Fatalf("expected created=false for existing secret")
	}
	if !resp.Ok {
		t.Fatalf("expected ok=true on existing-secret path")
	}
	if len(lister.addedVersions) != 1 {
		t.Fatalf("expected 1 AddSecretVersion, got %d", len(lister.addedVersions))
	}
}

func TestMintHealthOAuthJwt_NilNowDefaultsToTimeNow(t *testing.T) {
	// Cover the `if now == nil { now = time.Now }` branch.
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%q", rr.Code, rr.Body.String())
	}
}

func TestMintHealthOAuthJwt_WrongMethod(t *testing.T) {
	h := handleMintHealthOAuthJwt(&fakeSecretValueGetter{}, &fakeLister{},
		"test-project", fixedNow)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mint-health-oauth-jwt", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rr.Code)
	}
}

func TestMintHealthOAuthJwt_GetterError_502(t *testing.T) {
	getter := &fakeSecretValueGetter{err: errors.New("permission denied")}
	lister := &fakeLister{}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rr.Code)
	}
	if len(lister.createCalls) != 0 {
		t.Fatalf("expected no CreateSecret call when getter fails, got %d",
			len(lister.createCalls))
	}
}

func TestMintHealthOAuthJwt_EmptyJwtSecret_502(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: "",
	}}
	lister := &fakeLister{}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rr.Code)
	}
	if len(lister.createCalls) != 0 {
		t.Fatalf("expected no CreateSecret call on empty JWT_SECRET")
	}
}

func TestMintHealthOAuthJwt_CreateSecretError_502(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{createSecretErr: errors.New("backend down")}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestMintHealthOAuthJwt_CreateSecretPermissionDenied_502(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{
		createSecretErr: status.Error(codes.PermissionDenied,
			"caller missing roles/secretmanager.secretCreator"),
	}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "permission denied") {
		t.Fatalf("expected permission denied hint, got %q", rr.Body.String())
	}
}

func TestMintHealthOAuthJwt_AddVersionError_502(t *testing.T) {
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{addVersionErr: errors.New("backend down")}

	h := handleMintHealthOAuthJwt(getter, lister, "test-project", fixedNow)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newMintRequest(t))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestSignHS256Jwt_RoundTrip(t *testing.T) {
	claims := map[string]any{
		"sub": "test-user",
		"iat": int64(1700000000),
		"exp": int64(1700003600),
	}
	tok, err := signHS256Jwt(fakeJwtSecret, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got := verifyAndDecodeJwt(t, tok, fakeJwtSecret)
	if got["sub"] != "test-user" {
		t.Fatalf("sub mismatch: %v", got["sub"])
	}
}

func TestSignHS256Jwt_BadSignatureFailsVerify(t *testing.T) {
	tok, _ := signHS256Jwt(fakeJwtSecret, map[string]any{"sub": "x"})
	// Verify with WRONG secret — HMAC.Equal should reject.
	parts := strings.Split(tok, ".")
	enc := base64.RawURLEncoding
	mac := hmac.New(sha256.New, []byte("wrong-secret"))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := enc.EncodeToString(mac.Sum(nil))
	if hmac.Equal([]byte(parts[2]), []byte(wantSig)) {
		t.Fatalf("signature unexpectedly matched wrong secret")
	}
}

func TestMintHealthOAuthJwt_RoutedViaMux(t *testing.T) {
	// Smoke test that mux registration works end-to-end via newMuxWith.
	getter := &fakeSecretValueGetter{values: map[string]string{
		mintInputSecretName: fakeJwtSecret,
	}}
	lister := &fakeLister{}
	mux := newMuxWith(
		lister,
		&fakeIAMLister{},
		&fakeActivityLister{},
		getter,
		nil, // srcGetter (legacy test path → falls back to valueGetter)
		cfConfig{}, ghConfig{},
		http.DefaultClient,
		"test-project",
		"test-api-key",
	)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, srv.URL+"/mint-health-oauth-jwt", nil)
	req.Header.Set("X-Inventory-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}
