package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// `/sync-from-gcp/:name` で source secret の値を読むための「短命 self-grant」
// 機構。Refs #35 / ippoan/auth-worker#209。
//
// 背景: CLAUDE.md の方針で runtime SA は per-secret accessor を CF / GH
// proxy token の 2 個限定で持つ。任意 source を sync するには operator が
// 事前に gcloud で per-secret grant する必要があった。proxy 自身が
// CreateSecret した secret も同様で UX が破綻していた (#35)。
//
// 解決: sync 直前に runtime SA に対し target secret の `secretAccessor` を
// **TTL ≤ 10 分の Condition 付き binding** で grant、value を読み、defer で
// binding を削除する。cleanup 失敗しても CEL Condition で auto-expire するため
// dead binding は時間で消える (= 自己治癒)。
//
// 必要 IAM (runtime SA):
//   - secretmanager.secrets.getIamPolicy
//   - secretmanager.secrets.setIamPolicy
//   custom role `secretsInventoryTempAccessor` として CLAUDE.md に定義。
//   `roles/secretmanager.admin` は付けない (delete や value 直接 read を含む)。

const (
	// TTL hard cap。proxy 内で組み立てる Condition の expiry はこれを絶対に
	// 超えない。call site から TTL を渡せるが newLiveTempGrantManager で
	// validate するので、抜け道はこの定数の書き換えだけ (= CR で検知可能)。
	tempGrantMaxTTL = 10 * time.Minute

	// 追加する binding の Role は accessor 固定。signing oracle ではないので
	// admin 系を間違って渡せないよう定数化。
	tempGrantRole = "roles/secretmanager.secretAccessor"

	// Condition.Title。cleanup 時に「自分が追加した binding か」を判定する
	// マーカー。他の operator / system が同じ title を使わない命名にする。
	tempGrantConditionTitle = "secrets-inventory-temp-grant"

	// AccessSecretVersion を retry する deadline。IAM propagation lag は
	// 実測 1〜5 秒程度。8 秒見ておけば 99%ile に収まる。
	tempGrantReadDeadline = 8 * time.Second
	tempGrantReadBackoff  = 200 * time.Millisecond
	tempGrantReadBackoffCap = 2 * time.Second

	// SetIamPolicy が etag CAS で衝突 (Aborted) した時の retry 回数。
	// 並行 sync は per-secret に 2-3 件起きうる程度なので 3 で十分。
	tempGrantPolicyCASRetries = 3
)

// secretIAMPolicyClient は GetIamPolicy / SetIamPolicy を抽象化する。
// 本番では *secretmanager.Client、テストでは fake を差し込む。
type secretIAMPolicyClient interface {
	GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error)
	SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest) (*iampb.Policy, error)
}

// liveSecretIAMPolicyClient は *secretmanager.Client を secretIAMPolicyClient
// に適合させる thin wrapper。Client の方は `...opts ...gax.CallOption` を
// 受けるので interface に直接当てられない。
type liveSecretIAMPolicyClient struct{ c *secretmanager.Client }

func (l *liveSecretIAMPolicyClient) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return l.c.GetIamPolicy(ctx, req)
}

func (l *liveSecretIAMPolicyClient) SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	return l.c.SetIamPolicy(ctx, req)
}

// tempGrantManager は「source secret に短命 grant して値を読む」の境界。
// sync handler はこれを 1 source 1 read で呼ぶ。並行 call は etag CAS で吸収。
type tempGrantManager interface {
	GrantThenRead(ctx context.Context, secretName string) (string, error)
}

type liveTempGrantManager struct {
	iam       secretIAMPolicyClient
	reader    secretValueGetter
	projectID string
	member    string // "serviceAccount:<email>"
	ttl       time.Duration
	now       func() time.Time
}

func newLiveTempGrantManager(
	iam secretIAMPolicyClient,
	reader secretValueGetter,
	projectID, runtimeSAEmail string,
	ttl time.Duration,
) (*liveTempGrantManager, error) {
	if iam == nil {
		return nil, errors.New("iam client nil")
	}
	if reader == nil {
		return nil, errors.New("reader nil")
	}
	if projectID == "" {
		return nil, errors.New("projectID empty")
	}
	if runtimeSAEmail == "" {
		return nil, errors.New("runtime SA email empty")
	}
	if ttl <= 0 || ttl > tempGrantMaxTTL {
		return nil, fmt.Errorf("ttl %v out of range (0, %v]", ttl, tempGrantMaxTTL)
	}
	return &liveTempGrantManager{
		iam:       iam,
		reader:    reader,
		projectID: projectID,
		member:    "serviceAccount:" + runtimeSAEmail,
		ttl:       ttl,
		now:       time.Now,
	}, nil
}

// GrantThenRead はフルフロー: add conditional binding → read with retry →
// defer remove binding。
//
// 戻り string は呼び出し元 scope を抜けると Go GC に任せる。log / response
// body に echo してはならない (sync handler 側の責任)。
func (m *liveTempGrantManager) GrantThenRead(ctx context.Context, secretName string) (string, error) {
	resource := fmt.Sprintf("projects/%s/secrets/%s", m.projectID, secretName)
	expiry := m.now().UTC().Add(m.ttl)

	if err := m.mutatePolicy(ctx, resource, func(p *iampb.Policy) *iampb.Policy {
		return appendTempBinding(p, m.member, expiry)
	}); err != nil {
		return "", fmt.Errorf("temp grant add: %w", err)
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.mutatePolicy(cleanupCtx, resource, func(p *iampb.Policy) *iampb.Policy {
			return removeTempBinding(p, m.member, expiry)
		}); err != nil {
			// best-effort: Condition で auto-expire するため後続 sync は block
			// されない。次回 sync の add 時に同じ expiry の dead binding が
			// 残っていても無害 (appendTempBinding は別 binding として追加し
			// removeTempBinding は expiry timestamp 一致のものだけ消す)。
			log.Printf("TEMP_GRANT cleanup failed secret=%q expiry=%q err=%v (will auto-expire via CEL)",
				sanitizeLogValue(secretName), expiry.Format(time.RFC3339), err)
		}
	}()

	return m.readWithRetry(ctx, secretName)
}

// mutatePolicy は GetIamPolicy → mut() → SetIamPolicy を etag CAS で retry。
// SetIamPolicy が Aborted (= etag mismatch) を返したら最新 policy を再取得
// して mut を再適用する。これにより並行 add / remove で取りこぼしが起きない。
func (m *liveTempGrantManager) mutatePolicy(
	ctx context.Context,
	resource string,
	mut func(*iampb.Policy) *iampb.Policy,
) error {
	var lastErr error
	for i := 0; i < tempGrantPolicyCASRetries; i++ {
		policy, err := m.iam.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
			Resource: resource,
			Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
		})
		if err != nil {
			return fmt.Errorf("get iam policy: %w", err)
		}
		newPolicy := mut(policy)
		if _, err := m.iam.SetIamPolicy(ctx, &iampb.SetIamPolicyRequest{
			Resource: resource,
			Policy:   newPolicy,
		}); err != nil {
			if status.Code(err) == codes.Aborted {
				lastErr = err
				continue
			}
			return fmt.Errorf("set iam policy: %w", err)
		}
		return nil
	}
	return fmt.Errorf("set iam policy: etag CAS retry exhausted: %w", lastErr)
}

// readWithRetry は AccessSecretVersion を PermissionDenied で deadline まで
// 指数 backoff retry する。IAM propagation lag を吸収するための専用 retry で、
// 他のエラー (NotFound, Internal, etc) は即返す。
func (m *liveTempGrantManager) readWithRetry(ctx context.Context, secretName string) (string, error) {
	deadline := m.now().Add(tempGrantReadDeadline)
	backoff := tempGrantReadBackoff
	var lastErr error
	for {
		v, err := m.reader.Get(ctx, secretName)
		if err == nil {
			return v, nil
		}
		if status.Code(err) != codes.PermissionDenied {
			return "", err
		}
		lastErr = err
		if !m.now().Before(deadline) {
			return "", fmt.Errorf("temp grant: PermissionDenied after %v: %w", tempGrantReadDeadline, lastErr)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > tempGrantReadBackoffCap {
			backoff = tempGrantReadBackoffCap
		}
	}
}

// appendTempBinding は conditional binding を policy に追加して新 policy を返す。
// 既存 binding は触らない。policy が nil なら新規作成。
func appendTempBinding(p *iampb.Policy, member string, expiry time.Time) *iampb.Policy {
	if p == nil {
		p = &iampb.Policy{}
	}
	// version=3 を明示。Conditions 付き binding を扱うには必須。
	if p.Version < 3 {
		p.Version = 3
	}
	p.Bindings = append(p.Bindings, &iampb.Binding{
		Role:    tempGrantRole,
		Members: []string{member},
		Condition: &expr.Expr{
			Title:       tempGrantConditionTitle,
			Description: "Auto-grant by secrets-inventory-gcp for /sync-from-gcp source read",
			Expression:  tempGrantExpression(expiry),
		},
	})
	return p
}

// removeTempBinding は appendTempBinding で追加された自分の binding 1 個を
// 取り除く。「自分の」判定は (Role / Members / Condition.Title / Expression
// の expiry timestamp) が完全一致するもの。他者が追加した binding は触らない。
func removeTempBinding(p *iampb.Policy, member string, expiry time.Time) *iampb.Policy {
	if p == nil {
		return p
	}
	wantExpr := tempGrantExpression(expiry)
	filtered := make([]*iampb.Binding, 0, len(p.Bindings))
	for _, b := range p.Bindings {
		if isMatchingTempBinding(b, member, wantExpr) {
			continue
		}
		filtered = append(filtered, b)
	}
	p.Bindings = filtered
	return p
}

func isMatchingTempBinding(b *iampb.Binding, member, wantExpr string) bool {
	if b == nil || b.Role != tempGrantRole || b.Condition == nil {
		return false
	}
	if b.Condition.Title != tempGrantConditionTitle {
		return false
	}
	if strings.TrimSpace(b.Condition.Expression) != wantExpr {
		return false
	}
	if len(b.Members) != 1 || b.Members[0] != member {
		return false
	}
	return true
}

func tempGrantExpression(expiry time.Time) string {
	return fmt.Sprintf(`request.time < timestamp("%s")`, expiry.UTC().Format(time.RFC3339))
}

// grantingSrcReader は tempGrantManager を secretValueGetter interface に
// 適合させる adapter。sync handler は受け取った getter で Get するだけで
// temp grant が透過的に挟まる。
type grantingSrcReader struct{ mgr tempGrantManager }

func (g *grantingSrcReader) Get(ctx context.Context, name string) (string, error) {
	return g.mgr.GrantThenRead(ctx, name)
}
