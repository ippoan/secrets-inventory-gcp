package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// addVersionRequest は POST /add-version の body。`value` は **JSON body
// のみで運ぶ** (query / header に出さない = log / proxy 中継箇所に値が漏れる
// 経路を構造的に閉じる)。
type addVersionRequest struct {
	Value string `json:"value"`
}

// addVersionResponse は成功時の戻り値。`new_version` は GCP が割り当てた
// full resource name (`projects/.../secrets/<n>/versions/<id>`)。
//
// **値 (Value) は絶対に echo しない**。response field にも存在しない。
type addVersionResponse struct {
	Ok         bool   `json:"ok"`
	NewVersion string `json:"new_version"`
}

// createSecretRequest は POST /create-secret の body。
// `value` は **JSON body のみで運ぶ** (= add-version と同じ規約)。
type createSecretRequest struct {
	Value string `json:"value"`
}

// createSecretResponse は成功時の戻り値。
// `name` = 短縮 secret name、`new_version` = GCP が割り当てた version 1 の
// full resource name。fail_if_exists=false で既存 secret を再利用した場合も
// `created=false` で同じ shape を返す。
type createSecretResponse struct {
	Ok         bool   `json:"ok"`
	Name       string `json:"name"`
	Created    bool   `json:"created"`
	NewVersion string `json:"new_version"`
}

func main() {
	projectID := mustEnv("GCP_PROJECT_ID")
	apiKey := mustEnv("INVENTORY_API_KEY")
	// CF / GH 関連 env は worker (`secrets-inventory`) の
	// `CF_API_TOKEN` / `GITHUB_PAT` Secrets Store binding を本 proxy に集約
	// するための optional 設定 (Refs ippoan/secrets-inventory#45)。
	//
	// **optional 扱い**: deploy workflow と Cloud Run service の env 更新は
	// **コード deploy とは別の運用 step** (= Secret Manager に token 投入 +
	// per-secret IAM grant が前提) で行うため、env 未設定でも proxy 自体は
	// 起動する。未設定状態で `/cf/*` `/gh/*` を叩くと handler が 503 を返す
	// (= "endpoint not configured")。
	cfAccountID := os.Getenv("CF_ACCOUNT_ID")
	cfStoreID := os.Getenv("CF_STORE_ID")
	cfTokenSecret := os.Getenv("CF_TOKEN_SECRET_NAME")
	ghOrg := os.Getenv("GITHUB_ORG")
	ghTokenSecret := os.Getenv("GH_TOKEN_SECRET_NAME")
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

	// CF / GH endpoint 群で使う secret value getter。Secret Manager の
	// AccessSecretVersion を 5 分 TTL で cache する (= rotate 伝播 lag は
	// 最大 5 分許容)。
	valueGetter := newCachedSecretValueGetter(
		&liveSecretValueGetter{client: client, projectID: projectID},
		5*time.Minute,
	)

	mux := newMuxWith(
		&liveLister{c: client},
		&liveIAMLister{iam: iamClient, crm: crmClient},
		&livePolicyAnalyzer{svc: paService},
		valueGetter,
		cfConfig{accountID: cfAccountID, storeID: cfStoreID, tokenSecret: cfTokenSecret},
		ghConfig{org: ghOrg, tokenSecret: ghTokenSecret},
		http.DefaultClient,
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
//
// 基本は read-only だが、`AddSecretVersion` + `CreateSecret` のみ例外的に
// write を許す (= secrets-rotate-mcp 経由の rotation + new secret provisioning
// 用)。SA は `roles/secretmanager.secretVersionAdder` + `secretCreator` を
// 限定 grant する想定。`roles/secretmanager.admin` は与えない (= delete は
// 引き続き禁止)。
type secretLister interface {
	ListSecrets(ctx context.Context, parent string) ([]*secretmanagerpb.Secret, error)
	// LatestVersionCreateTime は親 secret (full name) の latest 1 version の
	// create_time を返す。Version 0 件なら (nil, nil)。
	LatestVersionCreateTime(ctx context.Context, secretName string) (*timestamppb.Timestamp, error)
	// LatestVersionName は親 secret (full name) の latest 1 version の
	// full name (`projects/.../secrets/<n>/versions/<id>`) を返す。
	// Version 0 件なら ("", nil)。TOCTOU 検証で「rotate 直前の version が
	// 想定通りか」を確認するのに使う。
	LatestVersionName(ctx context.Context, secretName string) (string, error)
	// AddSecretVersion は新しい version を投入する。返り値は GCP が
	// 割り当てた full version name。`value` は呼び出し側 (handler) で
	// **絶対に log しない / response に echo しない** ことを保証する。
	// この interface 境界では []byte で受け、Secret Manager の
	// SecretPayload.Data にそのまま渡す。
	AddSecretVersion(ctx context.Context, secretName string, value []byte) (string, error)
	// CreateSecret は parent (`projects/{p}`) 配下に short name の新 secret を
	// 作成する (automatic replication 固定)。
	//
	// 返り値:
	//   - createdName: 作成した secret の full name (`projects/.../secrets/{n}`)
	//   - alreadyExists: true なら既存 secret 衝突 (= GCP の AlreadyExists 相当)。
	//     この場合 createdName は full name を best-effort で組み立てて返す。
	//   - err: それ以外の upstream error
	//
	// caller (handler) は alreadyExists + fail_if_exists を見て 409 or
	// 再利用 (= 既存 secret に AddVersion を続行) を選ぶ。
	CreateSecret(ctx context.Context, parent, shortName string) (createdName string, alreadyExists bool, err error)
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

// LatestVersionName は ListSecretVersions(PageSize=1) で最新 version の
// full name を返す。Version が 0 件なら ("", nil) を返し、handler 側で
// TOCTOU 期待値が空文字 (= 「まだ version 無いはず」) と比較する。
func (l *liveLister) LatestVersionName(ctx context.Context, secretName string) (string, error) {
	it := l.c.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{
		Parent:   secretName,
		PageSize: 1,
	})
	v, err := it.Next()
	if errors.Is(err, iterator.Done) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v.GetName(), nil
}

// AddSecretVersion は親 secret に payload を 1 version 投入し、新 version の
// full name を返す。`value` は呼び出し側で log 禁止。エラーは upstream の
// gRPC error をそのまま返し、handler 側で 502 にラップする。
func (l *liveLister) AddSecretVersion(ctx context.Context, secretName string, value []byte) (string, error) {
	v, err := l.c.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: value,
		},
	})
	if err != nil {
		return "", err
	}
	return v.GetName(), nil
}

// CreateSecret は automatic replication で新 secret を作成する。既存衝突は
// gRPC `AlreadyExists` を `alreadyExists=true` に正規化して返し、caller が
// 409 / 再利用を選べるようにする。`SecretId` は short name (e.g. `MY_SECRET`)、
// `Parent` は `projects/{p}` 形式。
func (l *liveLister) CreateSecret(ctx context.Context, parent, shortName string) (string, bool, error) {
	s, err := l.c.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   parent,
		SecretId: shortName,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			// best-effort で full name を組み立てる (caller が再利用パスで
			// AddVersion に渡せるよう)
			return fmt.Sprintf("%s/secrets/%s", parent, shortName), true, nil
		}
		return "", false, err
	}
	return s.GetName(), false, nil
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
	valueGetter secretValueGetter,
	cfCfg cfConfig,
	ghCfg ghConfig,
	httpClient httpDoer,
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
	mux.Handle("/add-version", requireAPIKey(apiKey, handleAddSecretVersion(l, projectID)))
	mux.Handle("/create-secret", requireAPIKey(apiKey, handleCreateSecret(l, projectID)))
	// Refs ippoan/auth-worker#209: HEALTH_OAUTH_JWT mint endpoint.
	// JWT_SECRET の値を AccessSecretVersion で取って HS256 sign し、
	// HEALTH_OAUTH_JWT に新 version として書き込む 1 リクエスト endpoint。
	// 値は proxy memory 内のみ、応答 body には echo しない。
	mux.Handle("/mint-health-oauth-jwt", requireAPIKey(apiKey,
		handleMintHealthOAuthJwt(valueGetter, l, projectID, nil)))
	// Refs ippoan/auth-worker#209 PR4: 汎用 GCP→{CF, GitHub} sync endpoint。
	// GCP に既存の secret 値を、CF Secrets Store / GitHub Actions org secret
	// に同時 (or 個別) 投入する。値は proxy memory のみで取り回し、worker /
	// response body に echo しない。target ごとに per-secret accessor IAM 必要。
	mux.Handle("/sync-from-gcp/", requireAPIKey(apiKey,
		handleSyncFromGcp(valueGetter, cfCfg, ghCfg, httpClient)))
	// CF Secrets Store proxy (Refs ippoan/secrets-inventory#45)
	// `/cf/secrets` = list / create、`/cf/secrets/{id}` = rotate。
	// ServeMux の prefix match で `/cf/secrets/` (trailing slash) を {id}
	// 専用に流し、`/cf/secrets` (no slash) を list/create に分岐させる。
	// cfCfg / ghCfg が未設定 (= 必須 env 欠落) なら handler に届く前に 503 で
	// 即返す。これにより Cloud Run service の env 更新を **コード deploy と
	// 切り離して** 行える。
	mux.Handle("/cf/secrets/", requireAPIKey(apiKey, requireCfConfigured(cfCfg,
		handleCfRotate(valueGetter, cfCfg, httpClient))))
	mux.Handle("/cf/secrets", requireAPIKey(apiKey, requireCfConfigured(cfCfg,
		cfRootDispatcher(valueGetter, cfCfg, httpClient))))
	mux.Handle("/gh/secrets/", requireAPIKey(apiKey, requireGhConfigured(ghCfg,
		handleGhPut(valueGetter, ghCfg, httpClient))))
	mux.Handle("/gh/secrets", requireAPIKey(apiKey, requireGhConfigured(ghCfg,
		handleGhList(valueGetter, ghCfg, httpClient))))
	return mux
}

// requireCfConfigured は cfConfig が未設定なら 503 を即返す guard。これにより
// Cloud Run env 未投入の状態で deploy しても proxy 自体は up で、CF endpoint
// だけが "not configured" を返す degrade pattern が成立する。
func requireCfConfigured(cfg cfConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.configured() {
			http.Error(w, "endpoint not configured: missing CF_ACCOUNT_ID / CF_STORE_ID / CF_TOKEN_SECRET_NAME",
				http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireGhConfigured(cfg ghConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.configured() {
			http.Error(w, "endpoint not configured: missing GITHUB_ORG / GH_TOKEN_SECRET_NAME",
				http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cfRootDispatcher は `/cf/secrets` (trailing slash 無) を method 別に振り分け:
//   - GET  → list
//   - POST → create
//
// ServeMux 側で path 違いの handler を 2 つ登録する代わりに 1 つの handler 内
// で method 切り替えしているのは、Go 1.22+ の `http.HandleFunc("GET /...")`
// 構文を採用していない (compat 上 minimum) ためのワークアラウンド。
func cfRootDispatcher(getter secretValueGetter, cfg cfConfig, http_ httpDoer) http.Handler {
	listH := handleCfList(getter, cfg, http_)
	createH := handleCfCreate(getter, cfg, http_)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listH.ServeHTTP(w, r)
		case http.MethodPost:
			createH.ServeHTTP(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
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

// secretNamePattern は GCP Secret Manager の許す short name +
// 親 repo (secrets-inventory) で実運用される命名 (SCREAMING_SNAKE と kebab
// 両方) を許容する範囲に絞った正規表現。`/` 等 path injection 文字は不許可。
// GCP 側の許可文字は [A-Za-z0-9_-] で長さ 1-255 だが、実運用上は 128 chars
// 程度に制限して掛け違い予防。先頭は英字に強制する (GCP も英字 or _ を許容
// するが '_' 始まりは可読性が低い)。
var secretNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,127}$`)

// versionIdPattern は GCP の version id (`1`, `2`, ... or `latest`) の最小
// validate。TOCTOU 期待値として呼び出し側から渡される値が後段の log /
// 比較で injection されないことを確認する。GCP の Secret Manager version は
// 1 始まりの int で `latest` は alias。それ以外 (例えば `v1` や `MOCK`) は
// **不正値として 400** にする。
var versionIdPattern = regexp.MustCompile(`^([1-9][0-9]{0,15}|latest)$`)

// maxSecretValueBytes は POST /add-version の `value` 最大長 (= rotate-mcp
// tool の inputSchema.new_value.maxLength と揃える)。GCP Secret Manager 自身は
// payload 64 KiB まで許容。
const maxSecretValueBytes = 65536

// handleAddSecretVersion は POST /add-version のハンドラ。
//
// 親 repo (secrets-rotate-mcp) から呼ばれ、GCP Secret Manager に新 version
// を投入する。**値は JSON body の `value` field のみで受け取り**、
// log にも response にも一切 echo しない。
//
// クエリ:
//   - `name` (required): secret short name。`secretNamePattern` で validate
//
// header:
//   - `X-Inventory-API-Key` (required): shared secret 認証 (`requireAPIKey` で)
//   - `X-Actor-Email` (optional): 実操作者 email。actor audit log 用
//   - `X-Expected-Version-Id` (optional): TOCTOU 検証。指定すると AddVersion
//     直前に latest version id を確認し、不一致なら 409 で reject
//
// response:
//
//	200 { "ok": true, "new_version": "projects/.../secrets/<n>/versions/<id>" }
//	400 invalid input
//	401 unauthorized (上位 middleware)
//	409 expected_version_id mismatch (TOCTOU)
//	502 upstream GCP error
//
// 必要 IAM (Runtime SA, `secrets-inventory-viewer@...`):
//   - `roles/secretmanager.secretVersionAdder` を **対象 project 全 secret に**
//     付与する (rotate 対象 secret 範囲を絞りたい場合は per-secret IAM で限定)
//   - `roles/secretmanager.admin` は付けない (= delete / create-secret は不可)
func handleAddSecretVersion(l secretLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(name)

		expectedVersionId := r.Header.Get("X-Expected-Version-Id")
		if expectedVersionId != "" && !versionIdPattern.MatchString(expectedVersionId) {
			http.Error(w, "invalid expected_version_id", http.StatusBadRequest)
			return
		}

		// body は 64KiB + 小さな JSON envelope slack 程度で打ち切る。
		// それ以上はそもそも GCP 側でも reject されるが、proxy で先に打って
		// memory pressure と log 汚染を抑える。
		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var req addVersionRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if req.Value == "" {
			http.Error(w, "value is required", http.StatusBadRequest)
			return
		}
		if len(req.Value) > maxSecretValueBytes {
			http.Error(w, "value too large", http.StatusBadRequest)
			return
		}

		// 以後、`req.Value` は **絶対に log / error message / response に
		// echo しない**。意図しない経路で出ないよう scope を狭めるため、
		// ここで一度 []byte に変換して req は捨てる選択もあるが、Go の
		// string は immutable で defensive copy 不要なので req のまま使う。

		log.Printf("ADD_VERSION requested actor=%q target=%q expected_version=%q value_bytes=%d",
			actor, target, sanitizeLogValue(expectedVersionId), len(req.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		secretFullName := fmt.Sprintf("projects/%s/secrets/%s", projectID, name)

		// TOCTOU 検証 (`expected_version_id` 指定時のみ)。
		//
		// SecretManager に native if-match は無いので「list latest → 比較
		// → write」の best-effort check。比較〜write 間に他 client が
		// version 追加した場合は検出できないが、UI ヒューマンエラー対策と
		// しては十分。strict 一致が要件になった時は別途 KV lock を被せる。
		if expectedVersionId != "" {
			latest, err := l.LatestVersionName(ctx, secretFullName)
			if err != nil {
				log.Printf("ADD_VERSION list-latest failed actor=%q target=%q err=%v",
					actor, target, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			actualVersionId := shortName(latest) // "" if no versions yet
			if actualVersionId != expectedVersionId {
				log.Printf("ADD_VERSION TOCTOU mismatch actor=%q target=%q expected=%q actual=%q",
					actor, target, sanitizeLogValue(expectedVersionId), sanitizeLogValue(actualVersionId))
				http.Error(w, "expected_version_id mismatch", http.StatusConflict)
				return
			}
		}

		newVersionName, err := l.AddSecretVersion(ctx, secretFullName, []byte(req.Value))
		if err != nil {
			log.Printf("ADD_VERSION upstream failed actor=%q target=%q err=%v",
				actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		log.Printf("ADD_VERSION ok actor=%q target=%q new_version=%q",
			actor, target, sanitizeLogValue(newVersionName))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(addVersionResponse{
			Ok:         true,
			NewVersion: newVersionName,
		})
	})
}

// handleCreateSecret は POST /create-secret のハンドラ。
//
// 新 secret を作成し (automatic replication)、続けて initial value を version 1
// として投入する。`fail_if_exists=true` (default) で既存 name 衝突は 409。
//
// クエリ:
//   - `name` (required): secret short name。`secretNamePattern` で validate
//
// header:
//   - `X-Inventory-API-Key` (required): shared secret 認証
//   - `X-Actor-Email` (optional): 実操作者 email。actor audit log 用
//   - `X-Fail-If-Exists` (optional, default "true"):
//       - "true"  → 既存 name 衝突で 409、AddVersion は呼ばない
//       - "false" → 既存 secret を再利用して AddVersion を続行 (新 version)
//
// body:
//
//	{ "value": "<initial value>" }
//
// response:
//
//	200 { "ok": true, "name": "<n>", "created": true|false,
//	      "new_version": "projects/.../secrets/<n>/versions/<id>" }
//	400 invalid input
//	409 secret already exists (fail_if_exists=true)
//	502 upstream error
//
// 必要 IAM (Runtime SA):
//   - `roles/secretmanager.secretCreator` (= secrets.create)
//   - `roles/secretmanager.secretVersionAdder` (既存 /add-version 用、再利用)
//   `secretmanager.admin` は付けない (= delete 不可、最小権限)。
func handleCreateSecret(l secretLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(name)

		// X-Fail-If-Exists header の default = true (== 安全側)。明示的に
		// "false" を渡したときだけ既存 secret 再利用パスに入る。
		failIfExists := true
		if v := r.Header.Get("X-Fail-If-Exists"); v != "" {
			switch strings.ToLower(v) {
			case "false", "0", "no":
				failIfExists = false
			case "true", "1", "yes":
				failIfExists = true
			default:
				http.Error(w, "invalid X-Fail-If-Exists (use true|false)", http.StatusBadRequest)
				return
			}
		}

		// body 読み込み (add-version と同じ MaxBytesReader policy)
		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var req createSecretRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if req.Value == "" {
			http.Error(w, "value is required", http.StatusBadRequest)
			return
		}
		if len(req.Value) > maxSecretValueBytes {
			http.Error(w, "value too large", http.StatusBadRequest)
			return
		}

		log.Printf("CREATE_SECRET requested actor=%q target=%q fail_if_exists=%v value_bytes=%d",
			actor, target, failIfExists, len(req.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		parent := fmt.Sprintf("projects/%s", projectID)

		secretFullName, alreadyExists, err := l.CreateSecret(ctx, parent, name)
		if err != nil {
			log.Printf("CREATE_SECRET upstream failed actor=%q target=%q err=%v",
				actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if alreadyExists && failIfExists {
			log.Printf("CREATE_SECRET conflict actor=%q target=%q already exists",
				actor, target)
			http.Error(w, "secret already exists", http.StatusConflict)
			return
		}

		// 続けて initial value を投入。既存 secret 再利用パスでもここを通す。
		newVersionName, err := l.AddSecretVersion(ctx, secretFullName, []byte(req.Value))
		if err != nil {
			log.Printf("CREATE_SECRET add-version failed actor=%q target=%q err=%v",
				actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("CREATE_SECRET ok actor=%q target=%q created=%v new_version=%q",
			actor, target, !alreadyExists, sanitizeLogValue(newVersionName))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(createSecretResponse{
			Ok:         true,
			Name:       name,
			Created:    !alreadyExists,
			NewVersion: newVersionName,
		})
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
