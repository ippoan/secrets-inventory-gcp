package main

import (
	"context"
	"encoding/json"
	"errors"
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

	// 観測用
	gotProject string
	gotPolicyProject string
	keyCalls   []string
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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, "p", "k")
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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, "p", "topsecret")

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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, "p", "topsecret")
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
	mux := newMuxWith(f, &fakeIAMLister{}, "p", "topsecret")

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
	mux := newMuxWith(f, &fakeIAMLister{}, "p", "topsecret")

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
	mux := newMuxWith(&fakeLister{err: errors.New("boom")}, &fakeIAMLister{}, "p", "topsecret")
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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, "p", "topsecret")
	req := httptest.NewRequest(http.MethodGet, "/list-service-accounts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing api key should 401, got %d", rec.Code)
	}
}

func TestListServiceAccountsRejectsNonGet(t *testing.T) {
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{}, "p", "topsecret")
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
	mux := newMuxWith(&fakeLister{}, fakeIAM, "p", "topsecret")

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
	mux := newMuxWith(&fakeLister{}, &fakeIAMLister{saErr: errors.New("boom")}, "p", "topsecret")
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
	}, "p", "topsecret")
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
	}, "p", "topsecret")

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
	}, "p", "topsecret")
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
