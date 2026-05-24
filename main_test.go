package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeLister struct {
	mu sync.Mutex

	secrets   []*secretmanagerpb.Secret
	err       error
	gotParent string

	// LatestVersionCreateTime の挙動。`versionTimes[name]` を返し、
	// `versionErr` が non-nil なら全 secret について error。
	versionTimes map[string]*timestamppb.Timestamp
	versionErr   error

	// LatestVersionName の挙動。`latestNames[secretFullName]` を返し、
	// `latestNameErr` non-nil なら error。空 string は version 0 件相当。
	latestNames   map[string]string
	latestNameErr error

	// AddSecretVersion の挙動。`addedVersions` に呼び出しを記録、
	// `addVersionErr` non-nil なら error、`addVersionNameFn` で返却 name を
	// 計算 (default = `<secret>/versions/MOCK`)。
	addedVersions    []addCall
	addVersionErr    error
	addVersionNameFn func(secretName string) string
}

type addCall struct {
	secretName string
	value      []byte
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

func (f *fakeLister) LatestVersionName(_ context.Context, secretName string) (string, error) {
	if f.latestNameErr != nil {
		return "", f.latestNameErr
	}
	if f.latestNames == nil {
		return "", nil
	}
	return f.latestNames[secretName], nil
}

func (f *fakeLister) AddSecretVersion(_ context.Context, secretName string, value []byte) (string, error) {
	f.mu.Lock()
	// value を defensive copy する (caller の slice mutate に巻き込まれない)
	cp := make([]byte, len(value))
	copy(cp, value)
	f.addedVersions = append(f.addedVersions, addCall{secretName: secretName, value: cp})
	f.mu.Unlock()
	if f.addVersionErr != nil {
		return "", f.addVersionErr
	}
	if f.addVersionNameFn != nil {
		return f.addVersionNameFn(secretName), nil
	}
	return secretName + "/versions/MOCK", nil
}

// fakeActivityLister は saActivityLister の test 用 fake。`lastAuth` を
// SA email → RFC3339 で渡せば handler の取得結果を制御できる。`err` non-nil
// なら graceful degrade path (last_authenticated_at が全 SA で空文字) を
// 検証できる。
type fakeActivityLister struct {
	lastAuth map[string]string
	err      error

	// 観測用
	gotProject string
}

func (f *fakeActivityLister) LastAuthenticatedTimes(_ context.Context, project string) (map[string]string, error) {
	f.gotProject = project
	if f.err != nil {
		return nil, f.err
	}
	return f.lastAuth, nil
}

type fakeIAMLister struct {
	mu sync.Mutex

	sas    []*adminpb.ServiceAccount
	saErr  error
	policy *iampb.Policy
	polErr error

	// keys[saName] -> keys list、`keysErr` (全 SA で error)、`keysErrFor` (特定
	// SA だけ error) のいずれかで挙動制御。
	keys       map[string][]*adminpb.ServiceAccountKey
	keysErr    error
	keysErrFor string

	// SetServiceAccountDisabled の挙動制御。`disableErr` non-nil で常に error。
	disableErr error

	// 観測用
	gotProject       string
	gotPolicyProject string
	keyCalls         []string
	disableCalls     []disableCall
}

type disableCall struct {
	saName   string
	disabled bool
}

func (f *fakeIAMLister) ListServiceAccounts(_ context.Context, project string) ([]*adminpb.ServiceAccount, error) {
	f.gotProject = project
	return f.sas, f.saErr
}

func (f *fakeIAMLister) ListServiceAccountKeys(_ context.Context, saName string) ([]*adminpb.ServiceAccountKey, error) {
	f.mu.Lock()
	f.keyCalls = append(f.keyCalls, saName)
	f.mu.Unlock()
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	if f.keysErrFor != "" && saName == f.keysErrFor {
		return nil, errors.New("simulated per-sa key error")
	}
	if f.keys == nil {
		return nil, nil
	}
	return f.keys[saName], nil
}

func (f *fakeIAMLister) GetProjectIamPolicy(_ context.Context, project string) (*iampb.Policy, error) {
	f.gotPolicyProject = project
	return f.policy, f.polErr
}

func (f *fakeIAMLister) SetServiceAccountDisabled(_ context.Context, saName string, disabled bool) error {
	f.mu.Lock()
	f.disableCalls = append(f.disableCalls, disableCall{saName: saName, disabled: disabled})
	f.mu.Unlock()
	return f.disableErr
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
	// zero (epoch 0) timestamp も空文字に丸める path のカバー
	if got := tsToRFC3339(timestamppb.New(time.Time{})); got != "" {
		t.Errorf("zero time should be empty, got %q", got)
	}
}

func TestHealth(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "k")
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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
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
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

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
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

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
	mux := newMuxWith(&fakeLister{err: errors.New("boom")}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-secrets", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream error should 502, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// /list-service-accounts
// -----------------------------------------------------------------------------

func TestListServiceAccountsRequiresAPIKey(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing api key should 401, got %d", rec.Code)
	}
}

func TestListServiceAccountsRejectsNonGet(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST should 405, got %d", rec.Code)
	}
}

func TestListServiceAccountsOK(t *testing.T) {
	// SA 2 件、片方が roles + user-managed key 2 + system key 1、もう片方は
	// roles 空 + key 0 (= 後で workler 側で no-role flag が立つ前提)。
	saA := &adminpb.ServiceAccount{
		Name:        "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com",
		Email:       "sa-a@p.iam.gserviceaccount.com",
		DisplayName: "SA A",
		Description: "Used by feature X",
		UniqueId:    "100000000000000000001",
		Disabled:    false,
	}
	saB := &adminpb.ServiceAccount{
		Name:     "projects/p/serviceAccounts/sa-b@p.iam.gserviceaccount.com",
		Email:    "sa-b@p.iam.gserviceaccount.com",
		UniqueId: "100000000000000000002",
		Disabled: true,
	}
	keyT := timestamppb.New(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	fakeIAM := &fakeIAMLister{
		sas: []*adminpb.ServiceAccount{saA, saB},
		policy: &iampb.Policy{
			Bindings: []*iampb.Binding{
				{
					Role:    "roles/secretmanager.viewer",
					Members: []string{"serviceAccount:sa-a@p.iam.gserviceaccount.com", "user:alice@example.com"},
				},
				{
					Role:    "roles/storage.objectViewer",
					Members: []string{"serviceAccount:sa-a@p.iam.gserviceaccount.com"},
				},
				{
					Role:    "roles/secretmanager.viewer",
					Members: []string{"serviceAccount:sa-a@p.iam.gserviceaccount.com"}, // 重複 = dedup される
				},
				// sa-b には何も bind なし (= no-role)
			},
		},
		keys: map[string][]*adminpb.ServiceAccountKey{
			"projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com": {
				{
					Name:           "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com/keys/aaaa",
					KeyType:        adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
					ValidAfterTime: keyT,
				},
				{
					Name:    "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com/keys/bbbb",
					KeyType: adminpb.ListServiceAccountKeysRequest_SYSTEM_MANAGED,
				},
			},
		},
	}
	mux := newMuxWith(&fakeLister{}, fakeIAM, &fakeActivityLister{}, "p", "topsecret")

	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fakeIAM.gotProject != "p" {
		t.Errorf("gotProject = %q", fakeIAM.gotProject)
	}
	if fakeIAM.gotPolicyProject != "p" {
		t.Errorf("gotPolicyProject = %q", fakeIAM.gotPolicyProject)
	}

	var resp listServiceAccountsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ServiceAccounts) != 2 {
		t.Fatalf("got %d SAs", len(resp.ServiceAccounts))
	}

	// 順序は SA list と同じ (= a, b)
	a := resp.ServiceAccounts[0]
	if a.Email != "sa-a@p.iam.gserviceaccount.com" {
		t.Errorf("sa-a email = %q", a.Email)
	}
	if a.DisplayName != "SA A" {
		t.Errorf("sa-a display = %q", a.DisplayName)
	}
	if a.Description != "Used by feature X" {
		t.Errorf("sa-a description = %q", a.Description)
	}
	if a.Disabled {
		t.Errorf("sa-a should not be disabled")
	}
	if got := a.Roles; len(got) != 2 || got[0] != "roles/secretmanager.viewer" || got[1] != "roles/storage.objectViewer" {
		t.Errorf("sa-a roles = %v, want sorted + dedup", got)
	}
	if len(a.Keys) != 2 {
		t.Errorf("sa-a keys = %d, want 2", len(a.Keys))
	}
	if a.Keys[0].Id != "aaaa" || a.Keys[0].KeyType != "USER_MANAGED" {
		t.Errorf("sa-a key[0] = %+v", a.Keys[0])
	}
	if a.Keys[0].ValidAfter != "2026-03-01T00:00:00Z" {
		t.Errorf("sa-a key[0] valid_after = %q", a.Keys[0].ValidAfter)
	}
	if a.Keys[1].KeyType != "SYSTEM_MANAGED" {
		t.Errorf("sa-a key[1] type = %q", a.Keys[1].KeyType)
	}

	b := resp.ServiceAccounts[1]
	if !b.Disabled {
		t.Errorf("sa-b should be disabled")
	}
	if len(b.Roles) != 0 {
		t.Errorf("sa-b roles = %v, want []", b.Roles)
	}
	if len(b.Keys) != 0 {
		t.Errorf("sa-b keys = %v, want []", b.Keys)
	}

	// JSON body に PrivateKeyData っぽい field 名が含まれないことを固定
	// (= toKeyItem が material を漏らさない defense in depth)
	body := rec.Body.String()
	if strings.Contains(strings.ToLower(body), "private") {
		t.Errorf("response should not contain anything starting with 'private': %s", body)
	}
}

func TestListServiceAccountsUpstreamError(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{saErr: errors.New("boom")}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream error should 502, got %d", rec.Code)
	}
}

func TestListServiceAccountsPolicyFailDegrades(t *testing.T) {
	// policy 取得失敗は warning: SA は返す、roles 列は空。
	sa := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-x@p.iam.gserviceaccount.com",
		Email: "sa-x@p.iam.gserviceaccount.com",
	}
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas:    []*adminpb.ServiceAccount{sa},
		polErr: errors.New("simulated policy fetch failure"),
	}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp listServiceAccountsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.ServiceAccounts) != 1 {
		t.Fatalf("len = %d", len(resp.ServiceAccounts))
	}
	if len(resp.ServiceAccounts[0].Roles) != 0 {
		t.Errorf("roles should be empty on policy error, got %v", resp.ServiceAccounts[0].Roles)
	}
}

func TestListServiceAccountsKeysFailDegrades(t *testing.T) {
	saA := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com",
		Email: "sa-a@p.iam.gserviceaccount.com",
	}
	saB := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-b@p.iam.gserviceaccount.com",
		Email: "sa-b@p.iam.gserviceaccount.com",
	}
	keyT := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas: []*adminpb.ServiceAccount{saA, saB},
		keys: map[string][]*adminpb.ServiceAccountKey{
			"projects/p/serviceAccounts/sa-b@p.iam.gserviceaccount.com": {
				{
					Name:           "projects/p/serviceAccounts/sa-b@p.iam.gserviceaccount.com/keys/zzz",
					KeyType:        adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
					ValidAfterTime: keyT,
				},
			},
		},
		keysErrFor: "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com",
	}, &fakeActivityLister{}, "p", "topsecret")

	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp listServiceAccountsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.ServiceAccounts) != 2 {
		t.Fatalf("len = %d", len(resp.ServiceAccounts))
	}
	if len(resp.ServiceAccounts[0].Keys) != 0 {
		t.Errorf("sa-a should degrade to empty keys, got %v", resp.ServiceAccounts[0].Keys)
	}
	if len(resp.ServiceAccounts[1].Keys) != 1 {
		t.Errorf("sa-b should still have 1 key, got %d", len(resp.ServiceAccounts[1].Keys))
	}
}

func TestListServiceAccountsAllKeysFailDegrades(t *testing.T) {
	sa := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-x@p.iam.gserviceaccount.com",
		Email: "sa-x@p.iam.gserviceaccount.com",
	}
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas:     []*adminpb.ServiceAccount{sa},
		keysErr: errors.New("simulated global key fetch failure"),
	}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp listServiceAccountsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.ServiceAccounts[0].Keys) != 0 {
		t.Errorf("expected empty keys on global fetch failure")
	}
}

func TestInvertPolicyForServiceAccounts(t *testing.T) {
	policy := &iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role:    "roles/foo",
				Members: []string{"serviceAccount:a@p.iam.gserviceaccount.com", "user:alice@x"},
			},
			{
				Role:    "roles/bar",
				Members: []string{"serviceAccount:b@p.iam.gserviceaccount.com"},
			},
			{
				Role:    "roles/foo",
				Members: []string{"serviceAccount:a@p.iam.gserviceaccount.com"}, // 重複
			},
			{
				Role:    "roles/qux",
				Members: []string{"group:devs@x", "domain:example.com"},
			},
		},
	}
	got := invertPolicyForServiceAccounts(policy)
	if len(got) != 2 {
		t.Fatalf("expected 2 SA entries, got %d", len(got))
	}
	if r := got["a@p.iam.gserviceaccount.com"]; len(r) != 1 || r[0] != "roles/foo" {
		t.Errorf("a roles = %v", r)
	}
	if r := got["b@p.iam.gserviceaccount.com"]; len(r) != 1 || r[0] != "roles/bar" {
		t.Errorf("b roles = %v", r)
	}
}

func TestInvertPolicyNilSafe(t *testing.T) {
	got := invertPolicyForServiceAccounts(nil)
	if len(got) != 0 {
		t.Errorf("nil policy should yield empty map, got %v", got)
	}
}

func TestSortAndDedupRoles(t *testing.T) {
	in := []string{"roles/c", "roles/a", "roles/b", "roles/a"}
	got := sortAndDedupRoles(in)
	want := []string{"roles/a", "roles/b", "roles/c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %q, want %q", i, got[i], w)
		}
	}

	// 空入力は no-op
	if r := sortAndDedupRoles([]string{}); len(r) != 0 {
		t.Errorf("empty input should yield empty, got %v", r)
	}
}

func TestToKeyItemDoesNotIncludePrivateKey(t *testing.T) {
	keyT := timestamppb.New(time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	exp := timestamppb.New(time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
	k := &adminpb.ServiceAccountKey{
		Name:            "projects/p/serviceAccounts/x@p.iam.gserviceaccount.com/keys/abcdef",
		KeyType:         adminpb.ListServiceAccountKeysRequest_USER_MANAGED,
		ValidAfterTime:  keyT,
		ValidBeforeTime: exp,
		PrivateKeyData:  []byte("THIS_SHOULD_NEVER_LEAK"),
	}
	item := toKeyItem(k)
	if item.Id != "abcdef" {
		t.Errorf("id = %q", item.Id)
	}
	if item.KeyType != "USER_MANAGED" {
		t.Errorf("key_type = %q", item.KeyType)
	}
	if item.ValidAfter != "2026-05-22T00:00:00Z" {
		t.Errorf("valid_after = %q", item.ValidAfter)
	}
	if item.ValidBefore != "2026-11-22T00:00:00Z" {
		t.Errorf("valid_before = %q", item.ValidBefore)
	}
	// JSON serialized 形式に PrivateKeyData が含まれないことを字面で確認
	b, _ := json.Marshal(item)
	if strings.Contains(string(b), "THIS_SHOULD_NEVER_LEAK") {
		t.Fatalf("serialized item leaked private key material: %s", string(b))
	}
	if strings.Contains(strings.ToLower(string(b)), "private") {
		t.Fatalf("serialized item contains 'private' field: %s", string(b))
	}
}

func TestEmptyHelpers(t *testing.T) {
	if got := emptyIfNil(nil); len(got) != 0 {
		t.Errorf("emptyIfNil(nil) = %v", got)
	}
	if got := emptyIfNil([]string{"x"}); len(got) != 1 || got[0] != "x" {
		t.Errorf("emptyIfNil passthrough = %v", got)
	}
	if got := emptyKeysIfNil(nil); len(got) != 0 {
		t.Errorf("emptyKeysIfNil(nil) = %v", got)
	}
	if got := emptyKeysIfNil([]saKeyItem{{Id: "x"}}); len(got) != 1 {
		t.Errorf("emptyKeysIfNil passthrough = %v", got)
	}
}

func TestSaEmailFromFullResourceName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   "//iam.googleapis.com/projects/cloudsql-sv/serviceAccounts/sa@cloudsql-sv.iam.gserviceaccount.com",
			want: "sa@cloudsql-sv.iam.gserviceaccount.com",
		},
		{
			in:   "//iam.googleapis.com/projects/p/serviceAccounts/x",
			want: "x",
		},
		{in: "noslash", want: ""},
		{in: "", want: ""},
	}
	for _, c := range cases {
		if got := saEmailFromFullResourceName(c.in); got != c.want {
			t.Errorf("saEmailFromFullResourceName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseLastAuthenticatedTime(t *testing.T) {
	t.Run("typical activity payload", func(t *testing.T) {
		raw := []byte(`{"lastAuthenticatedTime":"2026-04-28T07:00:00Z","serviceAccount":{"projectNumber":"1"}}`)
		ts, ok := parseLastAuthenticatedTime(raw)
		if !ok || ts != "2026-04-28T07:00:00Z" {
			t.Fatalf("got (%q, %v), want (2026-04-28T07:00:00Z, true)", ts, ok)
		}
	})
	t.Run("missing field returns empty string but ok=true", func(t *testing.T) {
		raw := []byte(`{"serviceAccount":{"projectNumber":"1"}}`)
		ts, ok := parseLastAuthenticatedTime(raw)
		if !ok || ts != "" {
			t.Fatalf("got (%q, %v), want (\"\", true)", ts, ok)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		ts, ok := parseLastAuthenticatedTime(nil)
		if ok || ts != "" {
			t.Fatalf("got (%q, %v), want (\"\", false)", ts, ok)
		}
	})
	t.Run("malformed json", func(t *testing.T) {
		ts, ok := parseLastAuthenticatedTime([]byte("not-json"))
		if ok || ts != "" {
			t.Fatalf("got (%q, %v), want (\"\", false)", ts, ok)
		}
	})
}

func TestListServiceAccountsIncludesLastAuthenticatedAt(t *testing.T) {
	sa := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-x@p.iam.gserviceaccount.com",
		Email: "sa-x@p.iam.gserviceaccount.com",
	}
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas: []*adminpb.ServiceAccount{sa},
	}, &fakeActivityLister{
		lastAuth: map[string]string{
			"sa-x@p.iam.gserviceaccount.com": "2026-04-28T07:00:00Z",
		},
	}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp listServiceAccountsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ServiceAccounts) != 1 {
		t.Fatalf("len = %d", len(resp.ServiceAccounts))
	}
	if got := resp.ServiceAccounts[0].LastAuthenticatedAt; got != "2026-04-28T07:00:00Z" {
		t.Errorf("LastAuthenticatedAt = %q, want 2026-04-28T07:00:00Z", got)
	}
}

func TestListServiceAccountsActivityErrorDegradesGracefully(t *testing.T) {
	// Policy Analyzer 失敗時は SA 一覧は返るが last_authenticated_at は全 SA で空。
	// secrets の updated_at degrade pattern と同じ挙動。
	sa := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-x@p.iam.gserviceaccount.com",
		Email: "sa-x@p.iam.gserviceaccount.com",
	}
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas: []*adminpb.ServiceAccount{sa},
	}, &fakeActivityLister{
		err: errors.New("simulated policy analyzer permission denied"),
	}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (graceful degrade)", rec.Code)
	}
	var resp listServiceAccountsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ServiceAccounts) != 1 {
		t.Fatalf("len = %d", len(resp.ServiceAccounts))
	}
	if got := resp.ServiceAccounts[0].LastAuthenticatedAt; got != "" {
		t.Errorf("LastAuthenticatedAt = %q on activity error, want empty (degrade)", got)
	}
}

func TestListServiceAccountsMissingActivityForOneSA(t *testing.T) {
	// 2 SA 中 1 SA だけ Policy Analyzer に活動履歴がある (= 残り 1 つは未認証
	// or 期間外)。missing 側は空文字を expose する。
	saA := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-a@p.iam.gserviceaccount.com",
		Email: "sa-a@p.iam.gserviceaccount.com",
	}
	saB := &adminpb.ServiceAccount{
		Name:  "projects/p/serviceAccounts/sa-b@p.iam.gserviceaccount.com",
		Email: "sa-b@p.iam.gserviceaccount.com",
	}
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{
		sas: []*adminpb.ServiceAccount{saA, saB},
	}, &fakeActivityLister{
		lastAuth: map[string]string{
			"sa-b@p.iam.gserviceaccount.com": "2026-05-01T07:00:00Z",
		},
	}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp listServiceAccountsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ServiceAccounts) != 2 {
		t.Fatalf("len = %d", len(resp.ServiceAccounts))
	}
	byEmail := map[string]string{}
	for _, sa := range resp.ServiceAccounts {
		byEmail[sa.Email] = sa.LastAuthenticatedAt
	}
	if got := byEmail["sa-a@p.iam.gserviceaccount.com"]; got != "" {
		t.Errorf("sa-a LastAuthenticatedAt = %q, want empty", got)
	}
	if got := byEmail["sa-b@p.iam.gserviceaccount.com"]; got != "2026-05-01T07:00:00Z" {
		t.Errorf("sa-b LastAuthenticatedAt = %q, want 2026-05-01T07:00:00Z", got)
	}
}

// ------------------------------------------------------------
// /sa-disable / /sa-enable endpoints
// ------------------------------------------------------------

func TestSanitizeLogValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"normal@example.com", "normal@example.com"},
		{"with\nnewline", "withnewline"},
		{"with\r\ncrlf", "withcrlf"},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeLogValue(c.in); got != c.want {
			t.Errorf("sanitizeLogValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	got := sanitizeLogValue(string(long))
	if len(got) != 256+len("...") {
		t.Errorf("sanitizeLogValue trim len = %d, want %d", len(got), 256+len("..."))
	}
}

func TestSaDisable(t *testing.T) {
	fakeIAM := &fakeIAMLister{}
	mux := newMuxWith(&fakeLister{}, fakeIAM, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/sa-disable?email=foo@p.iam.gserviceaccount.com", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Actor-Email", "actor@example.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(fakeIAM.disableCalls) != 1 {
		t.Fatalf("disableCalls len = %d", len(fakeIAM.disableCalls))
	}
	got := fakeIAM.disableCalls[0]
	if got.saName != "projects/-/serviceAccounts/foo@p.iam.gserviceaccount.com" {
		t.Errorf("saName = %q", got.saName)
	}
	if !got.disabled {
		t.Errorf("disabled = false, want true (disable endpoint should set true)")
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestSaEnable(t *testing.T) {
	fakeIAM := &fakeIAMLister{}
	mux := newMuxWith(&fakeLister{}, fakeIAM, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/sa-enable?email=bar@p.iam.gserviceaccount.com", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(fakeIAM.disableCalls) != 1 || fakeIAM.disableCalls[0].disabled {
		t.Fatalf("calls = %+v (want 1 call with disabled=false)", fakeIAM.disableCalls)
	}
}

func TestSaDisableRequiresAPIKey(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/sa-disable?email=foo@p.iam.gserviceaccount.com", nil)
	// no X-Inventory-API-Key
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestSaDisableRejectsGET(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/sa-disable?email=foo@p.iam.gserviceaccount.com", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestSaDisableMissingEmail(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/sa-disable", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestSaDisableUpstreamError(t *testing.T) {
	fakeIAM := &fakeIAMLister{disableErr: errors.New("permission denied")}
	mux := newMuxWith(&fakeLister{}, fakeIAM, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/sa-disable?email=foo@p.iam.gserviceaccount.com", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// ------------------------------------------------------------
// /add-version endpoint (= rotate-mcp が叩く)
// ------------------------------------------------------------

// captureLog は log.SetOutput を差し替えて test 内の log 出力を bytes.Buffer
// に拾う。`value` の log leak 検出に使う。Cleanup で必ず元に戻す。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(prev)
		log.SetFlags(prevFlags)
	})
	return buf
}

func TestSecretNamePattern(t *testing.T) {
	ok := []string{
		"FOO",
		"foo",
		"FOO_BAR",
		"foo-bar",
		"a",
		"A1",
		"some-secret-name",
		"GH_SECRETS_INVENTORY_ORG_SECRETS_READ",
		"cf-secrets-inventory-secrets-store-read",
	}
	for _, n := range ok {
		if !secretNamePattern.MatchString(n) {
			t.Errorf("%q should match", n)
		}
	}
	bad := []string{
		"",
		"1FOO",                   // 先頭数字
		"_FOO",                   // 先頭 underscore
		"foo/bar",                // path injection
		"foo.bar",                // dot 不許可
		"foo bar",                // 空白
		strings.Repeat("a", 129), // 長すぎ
	}
	for _, n := range bad {
		if secretNamePattern.MatchString(n) {
			t.Errorf("%q should NOT match", n)
		}
	}
}

func TestVersionIdPattern(t *testing.T) {
	ok := []string{"1", "12345", "latest", "MOCK"}
	for _, v := range ok {
		if !versionIdPattern.MatchString(v) {
			t.Errorf("%q should match", v)
		}
	}
	bad := []string{"", "1.0", "1-2", "v1", strings.Repeat("a", 33)}
	for _, v := range bad {
		if versionIdPattern.MatchString(v) {
			t.Errorf("%q should NOT match", v)
		}
	}
}

func TestAddVersionRequiresAPIKey(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", strings.NewReader(`{"value":"x"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAddVersionRejectsNonPOST(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/add-version?name=FOO", nil)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestAddVersionMissingName(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/add-version", strings.NewReader(`{"value":"x"}`))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddVersionInvalidName(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	for _, bad := range []string{"FOO/BAR", "FOO.BAR", "1FOO", "_X", strings.Repeat("x", 129)} {
		t.Run(bad, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/add-version?name="+bad, strings.NewReader(`{"value":"x"}`))
			req.Header.Set("X-Inventory-API-Key", "topsecret")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("name=%q status = %d, want 400", bad, rec.Code)
			}
		})
	}
}

func TestAddVersionMalformedBody(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", strings.NewReader(`{not json`))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddVersionMissingValue(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", strings.NewReader(`{}`))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddVersionValueTooLarge(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	// 65537 chars (1 byte over limit). JSON envelope を含めても MaxBytesReader
	// 上限 (65536+1024) 内に収まる。
	val := strings.Repeat("a", maxSecretValueBytes+1)
	body, _ := json.Marshal(addVersionRequest{Value: val})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddVersionBodyExceedsMaxBytesReader(t *testing.T) {
	// MaxBytesReader 上限 (maxSecretValueBytes + 1024) を超える body は
	// io.ReadAll で error になり 400 で reject される (= memory pressure 防御)。
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	big := strings.Repeat("a", maxSecretValueBytes+2048)
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", strings.NewReader(big))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddVersionOK(t *testing.T) {
	f := &fakeLister{
		addVersionNameFn: func(secretName string) string {
			return secretName + "/versions/7"
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	const secretValue = "super-secret-payload-do-not-log-me"
	body, _ := json.Marshal(addVersionRequest{Value: secretValue})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=MY_SECRET", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Actor-Email", "actor@example.com")
	rec := httptest.NewRecorder()

	logBuf := captureLog(t)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp addVersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Ok {
		t.Errorf("ok = false")
	}
	if resp.NewVersion != "projects/p/secrets/MY_SECRET/versions/7" {
		t.Errorf("new_version = %q", resp.NewVersion)
	}

	// fake が 1 回呼ばれていて、value が proxy に届いていること
	if len(f.addedVersions) != 1 {
		t.Fatalf("addedVersions len = %d", len(f.addedVersions))
	}
	got := f.addedVersions[0]
	if got.secretName != "projects/p/secrets/MY_SECRET" {
		t.Errorf("secretName = %q", got.secretName)
	}
	if string(got.value) != secretValue {
		t.Errorf("value not forwarded as-is: %q", string(got.value))
	}

	// **値が response にも log にも出ていないこと** を固定 (= echo 禁止 spec)
	if strings.Contains(rec.Body.String(), secretValue) {
		t.Errorf("response leaked value: %s", rec.Body.String())
	}
	if strings.Contains(logBuf.String(), secretValue) {
		t.Errorf("log leaked value: %s", logBuf.String())
	}
	// log には actor / target / value_bytes は出ていてよい
	if !strings.Contains(logBuf.String(), "actor=\"actor@example.com\"") {
		t.Errorf("log should contain actor email, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "target=\"MY_SECRET\"") {
		t.Errorf("log should contain target name, got: %s", logBuf.String())
	}
}

func TestAddVersionUpstreamError(t *testing.T) {
	f := &fakeLister{addVersionErr: errors.New("PERMISSION_DENIED add version")}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	// upstream error message は response body にそのまま出さない
	// (502 ハンドラは generic "upstream error" を返す)
	if strings.Contains(rec.Body.String(), "PERMISSION_DENIED") {
		t.Errorf("response leaked upstream error: %s", rec.Body.String())
	}
}

func TestAddVersionTOCTOUMatch(t *testing.T) {
	// expected = actual の場合は write が走る
	f := &fakeLister{
		latestNames: map[string]string{
			"projects/p/secrets/FOO": "projects/p/secrets/FOO/versions/3",
		},
		addVersionNameFn: func(secretName string) string {
			return secretName + "/versions/4"
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Expected-Version-Id", "3")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(f.addedVersions) != 1 {
		t.Errorf("expected 1 add call after TOCTOU match, got %d", len(f.addedVersions))
	}
}

func TestAddVersionTOCTOUMismatch(t *testing.T) {
	// expected != actual の場合は write しない + 409 を返す
	f := &fakeLister{
		latestNames: map[string]string{
			"projects/p/secrets/FOO": "projects/p/secrets/FOO/versions/5",
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Expected-Version-Id", "3") // expected != actual (=5)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if len(f.addedVersions) != 0 {
		t.Errorf("expected 0 add calls on TOCTOU mismatch, got %d", len(f.addedVersions))
	}
}

func TestAddVersionTOCTOULatestError(t *testing.T) {
	// LatestVersionName が error の場合は 502 で fail-closed
	f := &fakeLister{latestNameErr: errors.New("rpc unavailable")}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Expected-Version-Id", "3")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if len(f.addedVersions) != 0 {
		t.Errorf("expected 0 add calls on latest-fetch error, got %d", len(f.addedVersions))
	}
}

func TestAddVersionTOCTOUExpectedEmptyButLatestExists(t *testing.T) {
	// 空 header (X-Expected-Version-Id 未送信) は expectedVersionId == "" となり
	// TOCTOU 検証を skip する。
	f := &fakeLister{
		latestNames: map[string]string{
			"projects/p/secrets/FOO": "projects/p/secrets/FOO/versions/9",
		},
		addVersionNameFn: func(secretName string) string {
			return secretName + "/versions/10"
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	// X-Expected-Version-Id を全く付けない → TOCTOU 検証 skip、即 write
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no TOCTOU check)", rec.Code)
	}
	if len(f.addedVersions) != 1 {
		t.Errorf("expected 1 add call, got %d", len(f.addedVersions))
	}
}

func TestAddVersionTOCTOUExpectedFirstVersion(t *testing.T) {
	// version 0 件の secret に expected_version_id="1" を投げる → mismatch (= 409)
	// (= 「先に手動で 1 つ作っておく必要」ケースを安全側で防ぐ)
	f := &fakeLister{
		latestNames: map[string]string{}, // FOO は無し
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Expected-Version-Id", "1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if len(f.addedVersions) != 0 {
		t.Errorf("expected 0 add calls, got %d", len(f.addedVersions))
	}
}

func TestAddVersionInvalidExpectedVersionId(t *testing.T) {
	// expected_version_id に injection 文字や長すぎる値が来た時は 400
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	for _, bad := range []string{"1.0", "1/2", "abc def", strings.Repeat("a", 33)} {
		t.Run(bad, func(t *testing.T) {
			body, _ := json.Marshal(addVersionRequest{Value: "x"})
			req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
			req.Header.Set("X-Inventory-API-Key", "topsecret")
			req.Header.Set("X-Expected-Version-Id", bad)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestAddVersionResponseShape(t *testing.T) {
	// response body の JSON 形状を固定 (= caller の TS 型と一致)
	f := &fakeLister{
		addVersionNameFn: func(secretName string) string {
			return secretName + "/versions/42"
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "v"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	bodyStr := strings.TrimSpace(rec.Body.String())
	want := `{"ok":true,"new_version":"projects/p/secrets/FOO/versions/42"}`
	if bodyStr != want {
		t.Errorf("body shape mismatch:\ngot:  %s\nwant: %s", bodyStr, want)
	}
}

func TestAddVersionEmptyBody(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", http.NoBody)
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// json.Unmarshal of empty bytes returns "unexpected end of JSON input" => 400
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (empty body)", rec.Code)
	}
}

// Coverage: TOCTOU mismatch log line で sanitizeLogValue の truncate path を
// exercise する (actual version name が 256 chars 超のとき)。
func TestAddVersionTOCTOULongActual(t *testing.T) {
	long := "projects/p/secrets/FOO/versions/" + strings.Repeat("z", 400)
	f := &fakeLister{
		latestNames: map[string]string{
			"projects/p/secrets/FOO": long,
		},
	}
	mux := newMuxWith(f, &fakeIAMLister{}, &fakeActivityLister{}, "p", "topsecret")

	body, _ := json.Marshal(addVersionRequest{Value: "x"})
	req := httptest.NewRequest(http.MethodPost, "/add-version?name=FOO", bytes.NewReader(body))
	req.Header.Set("X-Inventory-API-Key", "topsecret")
	req.Header.Set("X-Expected-Version-Id", "1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}
