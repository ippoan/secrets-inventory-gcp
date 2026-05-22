package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	policyanalyzer "google.golang.org/api/policyanalyzer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type secretItem struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at,omitempty"`
	// UpdatedAt = 最新 version の create_time (= 最後の rotation 時刻)。
	// Secret resource 自体に "updated" は無いため、Secret Manager の慣例
	// として「親 secret の latest version の create_time」をその意味で
	// expose する。Version が 0 件 (= 値未投入 / 全 destroy 済) の secret
	// は空文字。親 repo (secrets-inventory) の UI はこれを使って配布先
	// が GCP より古い (= rotation 反映漏れ) を ⚠ で警告する。
	UpdatedAt string            `json:"updated_at,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type listResponse struct {
	Secrets []secretItem `json:"secrets"`
}

// saKeyItem は SA key の **メタデータのみ**。`PrivateKeyData` (= 私有鍵 material)
// は絶対に含めない。defense in depth として handler test で空であることを固定する。
type saKeyItem struct {
	// Id は key の short name (= full resource name の末尾 segment)。
	Id string `json:"id"`
	// KeyType は "USER_MANAGED" / "SYSTEM_MANAGED"。
	KeyType string `json:"key_type"`
	// ValidAfter は `validAfterTime` = key 作成日時 (RFC3339)。
	ValidAfter string `json:"valid_after,omitempty"`
	// ValidBefore は `validBeforeTime` = key 失効日時 (RFC3339)。
	ValidBefore string `json:"valid_before,omitempty"`
}

// serviceAccountItem は IAM SA 1 件の inventory 用 view。
// roles は project IAM policy を逆引きした list (sorted unique)。
type serviceAccountItem struct {
	Email       string      `json:"email"`
	DisplayName string      `json:"display_name,omitempty"`
	Description string      `json:"description,omitempty"`
	UniqueId    string      `json:"unique_id"`
	Disabled    bool        `json:"disabled"`
	Roles       []string    `json:"roles"`
	Keys        []saKeyItem `json:"keys"`
	// LastAuthenticatedAt = Policy Analyzer
	// (`serviceAccountLastAuthentication` activity type) が返す
	// `activity.lastAuthenticatedTime` を RFC3339 でそのまま expose。
	//
	// データ無し (= 観測期間中 1 度も authenticate していない、または Policy
	// Analyzer 側 API が落ちている / 権限不足) のときは空文字。Worker UI は
	// 空文字 → "—" 表示 + "stale-auth" 系の audit 判定をかける。
	//
	// timestamp の精度は GCP 側で日次粒度に丸められる (08:00 UTC 固定の
	// `T07:00:00Z` 表記が docs にあるが、`07` 固定は古いリージョンのみで実際の
	// time は変わりうる) ので、worker 側では "N 日前" 表示に丸めて使う想定。
	LastAuthenticatedAt string `json:"last_authenticated_at,omitempty"`
}

type listServiceAccountsResponse struct {
	ServiceAccounts []serviceAccountItem `json:"service_accounts"`
}

func main() {
	projectID := mustEnv("GCP_PROJECT_ID")
	apiKey := mustEnv("INVENTORY_API_KEY")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("secretmanager client: %v", err)
	}
	defer client.Close()

	iamClient, err := iamadmin.NewIamClient(ctx)
	if err != nil {
		log.Fatalf("iam admin client: %v", err)
	}
	defer iamClient.Close()

	crmClient, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		log.Fatalf("resource manager projects client: %v", err)
	}
	defer crmClient.Close()

	// policyanalyzer は REST-based なので Close 不要。net/http の Client が
	// 内部で garbage collect されれば足りる。
	paService, err := policyanalyzer.NewService(ctx)
	if err != nil {
		log.Fatalf("policy analyzer service: %v", err)
	}

	mux := newMuxWith(
		&liveLister{c: client},
		&liveIAMLister{iam: iamClient, crm: crmClient},
		&livePolicyAnalyzer{svc: paService},
		projectID,
		apiKey,
	)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
log.Printf("secrets-inventory-gcp listening on :%s (project=%s)", port, projectID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("env %s is required", key)
	}
	return v
}

// secretLister は *secretmanager.Client の必要部分だけを切り出した interface。
// テストでは fake を差し込めるようにするための薄い境界。
type secretLister interface {
	ListSecrets(ctx context.Context, parent string) ([]*secretmanagerpb.Secret, error)
	// LatestVersionCreateTime は親 secret (full name) の latest 1 version の
	// create_time を返す。Version 0 件なら (nil, nil)。
	LatestVersionCreateTime(ctx context.Context, secretName string) (*timestamppb.Timestamp, error)
}

type liveLister struct {
	c *secretmanager.Client
}

func (l *liveLister) ListSecrets(ctx context.Context, parent string) ([]*secretmanagerpb.Secret, error) {
	var out []*secretmanagerpb.Secret
	it := l.c.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent:   parent,
		PageSize: 100,
	})
	for {
		s, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// LatestVersionCreateTime は ListSecretVersions(PageSize=1) で最新 version を
// 1 つだけ取って create_time を返す。SecretManager の version は create_time
// 降順で返るので PageSize=1 = latest。Version が 0 件なら (nil, nil)。
func (l *liveLister) LatestVersionCreateTime(ctx context.Context, secretName string) (*timestamppb.Timestamp, error) {
	it := l.c.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{
		Parent:   secretName,
		PageSize: 1,
	})
	v, err := it.Next()
	if errors.Is(err, iterator.Done) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v.GetCreateTime(), nil
}

// iamLister は IAM Admin + Resource Manager の必要部分だけ切り出した interface。
// テストでは fake を差し込む。基本は read-only (list + getIamPolicy) だが、
// **disable / enable のみ例外的に write 可** とする (reversible 操作、`delete`
// は実装しない)。これは secrets-inventory 全体の "テスト・即時復元用途で
// disable/enable のみ許可" の方針に合わせたもの (CLAUDE.md 参照)。
//
// 必要 IAM:
//   - `roles/iam.securityReviewer` (read)
//   - `iam.serviceAccounts.disable` + `.enable` (= 専用 custom role)
//   - `roles/iam.serviceAccountAdmin` 等の delete 含むロールは grant しない
type iamLister interface {
	ListServiceAccounts(ctx context.Context, project string) ([]*adminpb.ServiceAccount, error)
	ListServiceAccountKeys(ctx context.Context, saName string) ([]*adminpb.ServiceAccountKey, error)
	GetProjectIamPolicy(ctx context.Context, project string) (*iampb.Policy, error)
	// SetServiceAccountDisabled は `disabled=true` で disable、`false` で
	// enable する。冪等 (= 既に同じ状態なら 200 で成功)。delete は提供しない。
	SetServiceAccountDisabled(ctx context.Context, saName string, disabled bool) error
}

type liveIAMLister struct {
	iam *iamadmin.IamClient
	crm *resourcemanager.ProjectsClient
}

func (l *liveIAMLister) ListServiceAccounts(ctx context.Context, project string) ([]*adminpb.ServiceAccount, error) {
	var out []*adminpb.ServiceAccount
	it := l.iam.ListServiceAccounts(ctx, &adminpb.ListServiceAccountsRequest{
		Name:     fmt.Sprintf("projects/%s", project),
		PageSize: 100,
	})
	for {
		s, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (l *liveIAMLister) ListServiceAccountKeys(ctx context.Context, saName string) ([]*adminpb.ServiceAccountKey, error) {
	// keys.list は pagination 無しで一発で全 key 返す API。USER_MANAGED と
	// SYSTEM_MANAGED 両方含む。`KeyTypes` を指定しないと両方返る (= default)。
	resp, err := l.iam.ListServiceAccountKeys(ctx, &adminpb.ListServiceAccountKeysRequest{
		Name: saName,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetKeys(), nil
}

func (l *liveIAMLister) GetProjectIamPolicy(ctx context.Context, project string) (*iampb.Policy, error) {
	// Resource Manager v3 の Project に対する getIamPolicy。
	return l.crm.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: fmt.Sprintf("projects/%s", project),
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
}

// SetServiceAccountDisabled は IAM Admin の DisableServiceAccount /
// EnableServiceAccount を呼ぶ。Cloud Run service の attached SA に
// `iam.serviceAccounts.disable` + `.enable` が必要 (custom role 推奨)。
// **冪等**: 既に同じ disabled 状態の SA を再度叩いても GCP 側は no-op で
// success を返す。
func (l *liveIAMLister) SetServiceAccountDisabled(ctx context.Context, saName string, disabled bool) error {
	if disabled {
		return l.iam.DisableServiceAccount(ctx, &adminpb.DisableServiceAccountRequest{Name: saName})
	}
	return l.iam.EnableServiceAccount(ctx, &adminpb.EnableServiceAccountRequest{Name: saName})
}

// saActivityLister は Policy Analyzer の
// `serviceAccountLastAuthentication` activity を **SA email -> RFC3339
// 認証時刻** の map にまとめて返す。テスト用には fake を差し込む。
//
// 取得失敗 (権限不足 / API 未有効 / 障害) は **err non-nil**。caller 側で
// log + 空 map degrade を選ぶか fail-fast にするかを決める。本 proxy は
// "認証時刻は補助情報" 扱いで前者を採る (SA 一覧自体は出す)。
type saActivityLister interface {
	LastAuthenticatedTimes(ctx context.Context, project string) (map[string]string, error)
}

type livePolicyAnalyzer struct {
	svc *policyanalyzer.Service
}

// LastAuthenticatedTimes は project の全 SA の最終認証時刻を 1 endpoint
// で取りに行く (per-SA audit log read のような N+1 ではない)。Activities
// は内部 paging される ので Pages を用いて全 page を回収。
//
// response の Activity payload は `RawMessage` で運ばれてくるので、本 proxy
// が知っている `lastAuthenticatedTime` だけ抜き取る (= 値の漏出防止: 認証
// 内容まで Worker に渡さない)。
func (l *livePolicyAnalyzer) LastAuthenticatedTimes(ctx context.Context, project string) (map[string]string, error) {
	parent := fmt.Sprintf("projects/%s/locations/global/activityTypes/serviceAccountLastAuthentication", project)
	out := map[string]string{}
	call := l.svc.Projects.Locations.ActivityTypes.Activities.Query(parent).PageSize(1000)
	err := call.Pages(ctx, func(resp *policyanalyzer.GoogleCloudPolicyanalyzerV1QueryActivityResponse) error {
		for _, a := range resp.Activities {
			email := saEmailFromFullResourceName(a.FullResourceName)
			if email == "" {
				continue
			}
			ts, ok := parseLastAuthenticatedTime(a.Activity)
			if !ok || ts == "" {
				continue
			}
			out[email] = ts
		}
		return nil
	})
	return out, err
}

// saEmailFromFullResourceName は Policy Analyzer の `fullResourceName`
// (`//iam.googleapis.com/projects/.../serviceAccounts/<email>`) から末尾の
// email を取り出す。`/` が含まれない (= 想定外 shape) なら空文字。
func saEmailFromFullResourceName(s string) string {
	idx := strings.LastIndex(s, "/")
	if idx < 0 {
		return ""
	}
	return s[idx+1:]
}

// parseLastAuthenticatedTime は Activity payload (googleapi.RawMessage =
// []byte) から `lastAuthenticatedTime` を抜き取る。docs shape は:
//
//	{
//	  "lastAuthenticatedTime": "2026-04-28T07:00:00Z",
//	  "serviceAccount": { ... }
//	}
//
// 認証履歴が無い SA はそもそも response に含まれないが、
// `lastAuthenticatedTime` が空のケースを想定して 2 値返す。
func parseLastAuthenticatedTime(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var payload struct {
		LastAuthenticatedTime string `json:"lastAuthenticatedTime"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", false
	}
	return payload.LastAuthenticatedTime, true
}

func newMuxWith(
	l secretLister,
	iamL iamLister,
	actL saActivityLister,
	projectID, apiKey string,
) *http.ServeMux {
	mux := http.NewServeMux()
	// `/healthz` は Cloud Run / GFE の reserved path 扱いで Google edge が直接
	// 404 HTML を返してしまう (実 staging で再現)。`/health` に rename して
	// app に届くようにする。
	mux.HandleFunc("/health", handleHealth)
	mux.Handle("/list-secrets", requireAPIKey(apiKey, handleListSecrets(l, projectID)))
	mux.Handle("/list-service-accounts", requireAPIKey(apiKey, handleListServiceAccounts(iamL, actL, projectID)))
	mux.Handle("/sa-disable", requireAPIKey(apiKey, handleSetSADisabled(iamL, true)))
	mux.Handle("/sa-enable", requireAPIKey(apiKey, handleSetSADisabled(iamL, false)))
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"service":"secrets-inventory-gcp"}`))
}

func requireAPIKey(expected string, next http.Handler) http.Handler {
	expectedBytes := []byte(expected)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Inventory-API-Key")
		if subtle.ConstantTimeCompare([]byte(got), expectedBytes) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleSetSADisabled は POST /sa-disable / POST /sa-enable のハンドラ。
// query string `email` で対象 SA を指定、`X-Actor-Email` header に実操作者
// (CF Access JWT claim の email) を渡してもらう。actor は GCP 側 audit log
// (`principalEmail=secrets-inventory-viewer@...`) には載らないので、本 proxy
// が application log で記録する。両方を Cloud Logging で突合すれば操作の
// 完全な audit trail が取れる。
//
// 失敗 5xx は upstream IAM Admin の error をそのまま 502 で返し、proxy が
// 値の中身を解釈・露出しない。値漏れ防止のため request body は読まず、
// response body も `{ "ok": true }` のみ。
func handleSetSADisabled(l iamLister, disabled bool) http.Handler {
	action := "ENABLE"
	if disabled {
		action = "DISABLE"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, "missing email", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(email)
		log.Printf("SA %s requested actor=%q target=%q", action, actor, target)

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		// `projects/-/serviceAccounts/<email>` 形式で叩く (`-` で project は
		// SA email から自動推論される、IAM Admin API のお作法)。
		saName := fmt.Sprintf("projects/-/serviceAccounts/%s", email)
		if err := l.SetServiceAccountDisabled(ctx, saName, disabled); err != nil {
			log.Printf("SA %s failed actor=%q target=%q err=%v", action, actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		log.Printf("SA %s ok actor=%q target=%q", action, actor, target)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// sanitizeLogValue は log injection 対策。改行 / CR を削除し長さも制限する。
// principalEmail / target はどちらも外部 (Worker / GCP) から来るので、悪意ある
// payload で log 行を偽装される可能性を構造的に排除する。
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return s
}

func handleListSecrets(l secretLister, projectID string) http.Handler {
	parent := fmt.Sprintf("projects/%s", projectID)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		secrets, err := l.ListSecrets(ctx, parent)
		if err != nil {
			log.Printf("list secrets: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// Latest version の create_time を並列で取る (N=secret 数の goroutine)。
		// Secret Manager の version list API には list 内 batch が無いので
		// N+1 呼び出しが避けられない。N 個並列にして wall time を抑え、
		// 失敗した individual は updated_at 空で degrade (= UI は warning
		// 出さず ✓ のまま、log には残す)。
		updatedAt := make([]string, len(secrets))
		var wg sync.WaitGroup
		for i, s := range secrets {
			wg.Add(1)
			go func(i int, name string) {
				defer wg.Done()
				ts, vErr := l.LatestVersionCreateTime(ctx, name)
				if vErr != nil {
					log.Printf("latest version for %s: %v", name, vErr)
					return
				}
				updatedAt[i] = tsToRFC3339(ts)
			}(i, s.GetName())
		}
		wg.Wait()

		items := make([]secretItem, 0, len(secrets))
		for i, s := range secrets {
			items = append(items, secretItem{
				Name:      shortName(s.GetName()),
				CreatedAt: tsToRFC3339(s.GetCreateTime()),
				UpdatedAt: updatedAt[i],
				Labels:    s.GetLabels(),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listResponse{Secrets: items})
	})
}

func handleListServiceAccounts(l iamLister, actL saActivityLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		// SA 一覧 + project IAM policy + 最終認証時刻 (Policy Analyzer) を並列 fetch
		var sas []*adminpb.ServiceAccount
		var policy *iampb.Policy
		var lastAuth map[string]string
		var saErr, policyErr, actErr error
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			sas, saErr = l.ListServiceAccounts(ctx, projectID)
		}()
		go func() {
			defer wg.Done()
			policy, policyErr = l.GetProjectIamPolicy(ctx, projectID)
		}()
		go func() {
			defer wg.Done()
			lastAuth, actErr = actL.LastAuthenticatedTimes(ctx, projectID)
		}()
		wg.Wait()

		if saErr != nil {
			log.Printf("list service accounts: %v", saErr)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// policy 取得失敗は warning 扱い: SA 一覧自体は返し、roles 列だけ空。
		// secrets の updated_at 失敗時と同じ degrade pattern。
		rolesBySA := map[string][]string{}
		if policyErr != nil {
			log.Printf("get iam policy: %v", policyErr)
		} else if policy != nil {
			rolesBySA = invertPolicyForServiceAccounts(policy)
		}

		// Policy Analyzer 失敗も同じく warning 扱い: last_authenticated_at が
		// 全 SA 空文字になるだけで一覧自体は返す。Worker UI は空文字 → "—"。
		if actErr != nil {
			log.Printf("policy analyzer last auth: %v", actErr)
			lastAuth = nil
		}

		// 各 SA の keys を並列 fetch (N+1、log only degrade)。
		// 失敗した SA は keys 空で返す (= UI では "keys: ?" 表示にできる)。
		keysBySA := make([][]saKeyItem, len(sas))
		var wg2 sync.WaitGroup
		for i, sa := range sas {
			wg2.Add(1)
			go func(i int, saName, saEmail string) {
				defer wg2.Done()
				keys, kErr := l.ListServiceAccountKeys(ctx, saName)
				if kErr != nil {
					log.Printf("list keys for %s: %v", saEmail, kErr)
					return
				}
				items := make([]saKeyItem, 0, len(keys))
				for _, k := range keys {
					items = append(items, toKeyItem(k))
				}
				keysBySA[i] = items
			}(i, sa.GetName(), sa.GetEmail())
		}
		wg2.Wait()

		items := make([]serviceAccountItem, 0, len(sas))
		for i, sa := range sas {
			items = append(items, serviceAccountItem{
				Email:               sa.GetEmail(),
				DisplayName:         sa.GetDisplayName(),
				Description:         sa.GetDescription(),
				UniqueId:            sa.GetUniqueId(),
				Disabled:            sa.GetDisabled(),
				Roles:               emptyIfNil(rolesBySA[sa.GetEmail()]),
				Keys:                emptyKeysIfNil(keysBySA[i]),
				LastAuthenticatedAt: lastAuth[sa.GetEmail()],
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(listServiceAccountsResponse{ServiceAccounts: items})
	})
}

// invertPolicyForServiceAccounts は IAM policy の bindings を SA email → roles
// の逆引き map にする。`serviceAccount:` prefix の member だけ拾う (= user / group
// / domain は対象外、SA inventory が目的なので)。`deleted:serviceAccount:...`
// (= tombstone) も sufficient prefix 一致なら含めるが、現状の prefix は
// `serviceAccount:` のみ。重複した role は dedup する。
func invertPolicyForServiceAccounts(policy *iampb.Policy) map[string][]string {
	out := map[string][]string{}
	const prefix = "serviceAccount:"
	for _, b := range policy.GetBindings() {
		role := b.GetRole()
		for _, m := range b.GetMembers() {
			if !strings.HasPrefix(m, prefix) {
				continue
			}
			email := m[len(prefix):]
			out[email] = append(out[email], role)
		}
	}
	for email, roles := range out {
		out[email] = sortAndDedupRoles(roles)
	}
	return out
}

func sortAndDedupRoles(roles []string) []string {
	if len(roles) == 0 {
		return roles
	}
	sort.Strings(roles)
	dedup := roles[:0]
	prev := ""
	for i, r := range roles {
		if i == 0 || r != prev {
			dedup = append(dedup, r)
		}
		prev = r
	}
	return dedup
}

// toKeyItem は SA key proto を **メタデータのみ** の view に縮約する。
// `PrivateKeyData` (= 私有鍵 material) は **絶対に含めない**。
func toKeyItem(k *adminpb.ServiceAccountKey) saKeyItem {
	return saKeyItem{
		Id:          shortName(k.GetName()),
		KeyType:     k.GetKeyType().String(),
		ValidAfter:  tsToRFC3339(k.GetValidAfterTime()),
		ValidBefore: tsToRFC3339(k.GetValidBeforeTime()),
	}
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func emptyKeysIfNil(s []saKeyItem) []saKeyItem {
	if s == nil {
		return []saKeyItem{}
	}
	return s
}

func shortName(fullName string) string {
	idx := strings.LastIndex(fullName, "/")
	if idx < 0 {
		return fullName
	}
	return fullName[idx+1:]
}

func tsToRFC3339(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	t := ts.AsTime()
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
