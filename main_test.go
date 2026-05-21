package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeLister struct {
	secrets   []*secretmanagerpb.Secret
	err       error
	gotParent string

	// LatestVersionCreateTime の挙動。`versionTimes[name]` を返し、
	// `versionErr` が non-nil なら全 secret について error。
	versionTimes map[string]*timestamppb.Timestamp
	versionErr   error
}

func (f *fakeLister) ListSecrets(_ context.Context, parent string) ([]*secretmanagerpb.Secret, error) {
	f.gotParent = parent
	return f.secrets, f.err
}

func (f *fakeLister) LatestVersionCreateTime(_ context.Context, secretName string) (*timestamppb.Timestamp, error) {
	if f.versionErr != nil {
		return nil, f.versionErr
	}
	if f.versionTimes == nil {
		return nil, nil
	}
	return f.versionTimes[secretName], nil
}

func TestShortName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"projects/foo/secrets/MY_SECRET", "MY_SECRET"},
		{"LITERAL", "LITERAL"},
		{"", ""},
	}
	for _, c := range cases {
		if got := shortName(c.in); got != c.want {
			t.Errorf("shortName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTsToRFC3339(t *testing.T) {
	if tsToRFC3339(nil) != "" {
		t.Error("nil ts should be empty string")
	}
	ts := timestamppb.New(time.Date(2026, 5, 21, 12, 34, 56, 0, time.UTC))
	if got := tsToRFC3339(ts); got != "2026-05-21T12:34:56Z" {
		t.Errorf("got %q", got)
	}
}

func TestHealth(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, "p", "k")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestListSecretsRequiresAPIKey(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, "p", "topsecret")

	// no header
	req := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing api key should 401, got %d", rec.Code)
	}

	// wrong key
	req2 := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	req2.Header.Set("X-Inventory-API-Key", "wrong")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong api key should 401, got %d", rec2.Code)
	}
}

func TestListSecretsRejectsNonGet(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/list-secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST should 405, got %d", rec.Code)
	}
}

func TestListSecretsOK(t *testing.T) {
	now := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	rotA := timestamppb.New(time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC))
	f := &fakeLister{
		secrets: []*secretmanagerpb.Secret{
			{Name: "projects/p/secrets/A", CreateTime: now, Labels: map[string]string{"env": "prod"}},
			{Name: "projects/p/secrets/B", CreateTime: now},
		},
		versionTimes: map[string]*timestamppb.Timestamp{
			// A は rotate されているが B は version 未投入のシナリオ
			"projects/p/secrets/A": rotA,
		},
	}
	mux := newMuxWith(f, "p", "topsecret")

	req := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if f.gotParent != "projects/p" {
		t.Errorf("parent = %q, want projects/p", f.gotParent)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Secrets) != 2 {
		t.Fatalf("got %d secrets", len(resp.Secrets))
	}
	if resp.Secrets[0].Name != "A" {
		t.Errorf("first secret name = %q", resp.Secrets[0].Name)
	}
	if resp.Secrets[0].Labels["env"] != "prod" {
		t.Errorf("labels = %v", resp.Secrets[0].Labels)
	}
	if resp.Secrets[0].CreatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("created_at = %q", resp.Secrets[0].CreatedAt)
	}
	if resp.Secrets[0].UpdatedAt != "2026-04-10T09:00:00Z" {
		t.Errorf("updated_at = %q, want 2026-04-10T09:00:00Z", resp.Secrets[0].UpdatedAt)
	}
	if resp.Secrets[1].UpdatedAt != "" {
		t.Errorf("B updated_at = %q, want empty (no version)", resp.Secrets[1].UpdatedAt)
	}
	if resp.Secrets[1].Labels != nil && len(resp.Secrets[1].Labels) != 0 {
		t.Errorf("expected no labels on B, got %v", resp.Secrets[1].Labels)
	}
}

func TestListSecretsVersionFetchFailDegradesToEmpty(t *testing.T) {
	// Individual version fetch が失敗しても全体 200 で updated_at 空に degrade。
	now := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	f := &fakeLister{
		secrets: []*secretmanagerpb.Secret{
			{Name: "projects/p/secrets/A", CreateTime: now},
		},
		versionErr: errors.New("simulated version API failure"),
	}
	mux := newMuxWith(f, "p", "topsecret")

	req := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (want 200 even if version fetch fails)", rec.Code)
	}
	var resp listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Secrets) != 1 {
		t.Fatalf("got %d secrets", len(resp.Secrets))
	}
	if resp.Secrets[0].UpdatedAt != "" {
		t.Errorf("updated_at = %q, want empty (degraded)", resp.Secrets[0].UpdatedAt)
	}
	if resp.Secrets[0].CreatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("created_at = %q, want unchanged", resp.Secrets[0].CreatedAt)
	}
}

func TestListSecretsUpstreamError(t *testing.T) {
	mux := newMuxWith(&fakeLister{err: errors.New("boom")}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream error should 502, got %d", rec.Code)
	}
}
