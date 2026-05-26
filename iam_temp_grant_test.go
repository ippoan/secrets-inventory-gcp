package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"google.golang.org/genproto/googleapis/type/expr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeIAMPolicyClient は policy を in-memory に持つ偽 client。
// concurrent safe (テストで並行 mutate を assert したいため)。
type fakeIAMPolicyClient struct {
	mu     sync.Mutex
	policy *iampb.Policy

	getErr error
	setErr error

	// SetIamPolicy を最初の N 回だけ Aborted で返す。CAS retry 試験用。
	abortedRemaining atomic.Int32

	getCalls atomic.Int32
	setCalls atomic.Int32
}

func newFakeIAMPolicyClient() *fakeIAMPolicyClient {
	return &fakeIAMPolicyClient{policy: &iampb.Policy{Version: 3}}
}

func (f *fakeIAMPolicyClient) GetIamPolicy(_ context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	f.getCalls.Add(1)
	if f.getErr != nil {
		return nil, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// clone (proto Policy は pointers を持つので shallow copy で十分なテストでは
	// ないが、本テストでは bindings の append しかしないので shallow + slice copy)
	clone := &iampb.Policy{
		Version:  f.policy.Version,
		Etag:     append([]byte(nil), f.policy.Etag...),
		Bindings: append([]*iampb.Binding(nil), f.policy.Bindings...),
	}
	return clone, nil
}

func (f *fakeIAMPolicyClient) SetIamPolicy(_ context.Context, req *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	f.setCalls.Add(1)
	if f.abortedRemaining.Load() > 0 {
		f.abortedRemaining.Add(-1)
		return nil, status.Error(codes.Aborted, "etag mismatch (test)")
	}
	if f.setErr != nil {
		return nil, f.setErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy = req.Policy
	return req.Policy, nil
}

// fakeRetryGetter は最初の N 回を PermissionDenied、その後は値を返す。
type fakeRetryGetter struct {
	failsRemaining atomic.Int32
	value          string
	calls          atomic.Int32
}

func (f *fakeRetryGetter) Get(_ context.Context, _ string) (string, error) {
	f.calls.Add(1)
	if f.failsRemaining.Load() > 0 {
		f.failsRemaining.Add(-1)
		return "", status.Error(codes.PermissionDenied, "iam propagation lag (test)")
	}
	return f.value, nil
}

func TestNewLiveTempGrantManager_Validation(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "v"}
	cases := []struct {
		name      string
		iam       secretIAMPolicyClient
		reader    secretValueGetter
		project   string
		sa        string
		ttl       time.Duration
		wantSubst string
	}{
		{"nil iam", nil, reader, "p", "sa@x.iam", time.Minute, "iam client nil"},
		{"nil reader", iam, nil, "p", "sa@x.iam", time.Minute, "reader nil"},
		{"empty project", iam, reader, "", "sa@x.iam", time.Minute, "projectID"},
		{"empty sa", iam, reader, "p", "", time.Minute, "runtime SA"},
		{"zero ttl", iam, reader, "p", "sa@x.iam", 0, "ttl"},
		{"ttl over cap", iam, reader, "p", "sa@x.iam", tempGrantMaxTTL + time.Second, "ttl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newLiveTempGrantManager(tc.iam, tc.reader, tc.project, tc.sa, tc.ttl)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantSubst)
			}
			if !strings.Contains(err.Error(), tc.wantSubst) {
				t.Fatalf("err=%q want substring %q", err.Error(), tc.wantSubst)
			}
		})
	}
}

func TestAppendTempBinding_AddsConditionalBinding(t *testing.T) {
	expiry := time.Date(2026, 5, 26, 3, 0, 0, 0, time.UTC)
	p := &iampb.Policy{Version: 1, Bindings: []*iampb.Binding{
		{Role: "roles/secretmanager.viewer", Members: []string{"user:alice@example.com"}},
	}}
	out := appendTempBinding(p, "serviceAccount:sa@x.iam", expiry)
	if out.Version != 3 {
		t.Fatalf("version=%d want 3 (Conditions require v3)", out.Version)
	}
	if len(out.Bindings) != 2 {
		t.Fatalf("len(bindings)=%d want 2", len(out.Bindings))
	}
	b := out.Bindings[1]
	if b.Role != tempGrantRole {
		t.Errorf("role=%q want %q", b.Role, tempGrantRole)
	}
	if len(b.Members) != 1 || b.Members[0] != "serviceAccount:sa@x.iam" {
		t.Errorf("members=%v want [serviceAccount:sa@x.iam]", b.Members)
	}
	if b.Condition == nil || b.Condition.Title != tempGrantConditionTitle {
		t.Fatalf("condition missing or wrong title: %+v", b.Condition)
	}
	wantExpr := `request.time < timestamp("2026-05-26T03:00:00Z")`
	if b.Condition.Expression != wantExpr {
		t.Errorf("expr=%q want %q", b.Condition.Expression, wantExpr)
	}
}

func TestAppendTempBinding_NilPolicy(t *testing.T) {
	expiry := time.Date(2026, 5, 26, 3, 0, 0, 0, time.UTC)
	out := appendTempBinding(nil, "serviceAccount:sa@x.iam", expiry)
	if out == nil || out.Version != 3 || len(out.Bindings) != 1 {
		t.Fatalf("nil policy not handled: %+v", out)
	}
}

func TestRemoveTempBinding_RemovesOnlyMatching(t *testing.T) {
	expiry := time.Date(2026, 5, 26, 3, 0, 0, 0, time.UTC)
	otherExpiry := time.Date(2026, 5, 26, 4, 0, 0, 0, time.UTC)
	mine := &iampb.Binding{
		Role: tempGrantRole, Members: []string{"serviceAccount:sa@x.iam"},
		Condition: &expr.Expr{Title: tempGrantConditionTitle, Expression: tempGrantExpression(expiry)},
	}
	otherSAMine := &iampb.Binding{
		Role: tempGrantRole, Members: []string{"serviceAccount:other@x.iam"},
		Condition: &expr.Expr{Title: tempGrantConditionTitle, Expression: tempGrantExpression(expiry)},
	}
	mineDifferentExpiry := &iampb.Binding{
		Role: tempGrantRole, Members: []string{"serviceAccount:sa@x.iam"},
		Condition: &expr.Expr{Title: tempGrantConditionTitle, Expression: tempGrantExpression(otherExpiry)},
	}
	permanent := &iampb.Binding{
		Role: tempGrantRole, Members: []string{"serviceAccount:sa@x.iam"},
		// no Condition = permanent
	}
	wrongTitle := &iampb.Binding{
		Role: tempGrantRole, Members: []string{"serviceAccount:sa@x.iam"},
		Condition: &expr.Expr{Title: "different-title", Expression: tempGrantExpression(expiry)},
	}
	p := &iampb.Policy{Version: 3, Bindings: []*iampb.Binding{
		mine, otherSAMine, mineDifferentExpiry, permanent, wrongTitle,
	}}
	out := removeTempBinding(p, "serviceAccount:sa@x.iam", expiry)
	if len(out.Bindings) != 4 {
		t.Fatalf("len after remove=%d want 4, got bindings=%+v", len(out.Bindings), out.Bindings)
	}
	for _, b := range out.Bindings {
		if isMatchingTempBinding(b, "serviceAccount:sa@x.iam", tempGrantExpression(expiry)) {
			t.Errorf("matching binding still present: %+v", b)
		}
	}
}

func TestGrantThenRead_HappyPath(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "secret-payload"}
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	got, err := mgr.GrantThenRead(context.Background(), "MY_SECRET")
	if err != nil {
		t.Fatalf("GrantThenRead: %v", err)
	}
	if got != "secret-payload" {
		t.Errorf("value=%q want secret-payload", got)
	}
	// add + remove = 2 set calls minimum
	if iam.setCalls.Load() < 2 {
		t.Errorf("setCalls=%d want >=2 (add + remove)", iam.setCalls.Load())
	}
	// after cleanup: no matching binding should remain
	iam.mu.Lock()
	defer iam.mu.Unlock()
	for _, b := range iam.policy.Bindings {
		if b.Role == tempGrantRole && b.Condition != nil && b.Condition.Title == tempGrantConditionTitle {
			t.Errorf("cleanup left binding: %+v", b)
		}
	}
}

func TestGrantThenRead_RetryOnIAMPropagationLag(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "ok"}
	reader.failsRemaining.Store(2) // 1st + 2nd Get → PermissionDenied、3rd → ok
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	start := time.Now()
	got, err := mgr.GrantThenRead(context.Background(), "MY_SECRET")
	if err != nil {
		t.Fatalf("GrantThenRead: %v", err)
	}
	if got != "ok" {
		t.Errorf("value=%q want ok", got)
	}
	if reader.calls.Load() != 3 {
		t.Errorf("reader.calls=%d want 3", reader.calls.Load())
	}
	// 2 retries with 200ms + 400ms backoff = ~600ms
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("elapsed=%v expected backoff", elapsed)
	}
}

func TestGrantThenRead_NonPermissionDeniedReturnsImmediately(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "ok"}
	reader.failsRemaining.Store(0)
	// inject a non-PermissionDenied error via wrapper
	wrapped := &errorOnceGetter{inner: reader, err: status.Error(codes.NotFound, "boom")}
	mgr, err := newLiveTempGrantManager(iam, wrapped, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	_, err = mgr.GrantThenRead(context.Background(), "X")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want NotFound, got %v", err)
	}
	if wrapped.calls != 1 {
		t.Errorf("wrapped.calls=%d want 1 (no retry on non-PermissionDenied)", wrapped.calls)
	}
}

type errorOnceGetter struct {
	inner secretValueGetter
	err   error
	calls int
}

func (g *errorOnceGetter) Get(ctx context.Context, name string) (string, error) {
	g.calls++
	return "", g.err
}

func TestGrantThenRead_CAS_RetryOnAborted(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	iam.abortedRemaining.Store(2) // first 2 SetIamPolicy calls return Aborted
	reader := &fakeRetryGetter{value: "v"}
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	got, err := mgr.GrantThenRead(context.Background(), "X")
	if err != nil {
		t.Fatalf("GrantThenRead: %v", err)
	}
	if got != "v" {
		t.Errorf("value=%q want v", got)
	}
	// add: 1st Aborted, 2nd Aborted, 3rd ok = 3 set calls just for add.
	// then cleanup: 1 more set call (no Aborted left) = 4 total.
	if iam.setCalls.Load() != 4 {
		t.Errorf("setCalls=%d want 4", iam.setCalls.Load())
	}
}

func TestGrantThenRead_CleanupFailureDoesntFailCall(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "v"}
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	// arrange: cleanup の SetIamPolicy が落ちる
	// 1st set (add) succeeds, then we set setErr for cleanup
	// we need a hook; simplest: wrap iam so 2nd+ Set errors
	wrappedIAM := &iamSetErrorAfterN{inner: iam, n: 1, err: errors.New("upstream 500")}
	mgr.iam = wrappedIAM
	got, err := mgr.GrantThenRead(context.Background(), "X")
	if err != nil {
		t.Fatalf("GrantThenRead unexpectedly failed: %v", err)
	}
	if got != "v" {
		t.Errorf("value=%q want v", got)
	}
	// cleanup attempted at least once
	if wrappedIAM.setCalls < 2 {
		t.Errorf("setCalls=%d want >=2", wrappedIAM.setCalls)
	}
}

type iamSetErrorAfterN struct {
	inner    secretIAMPolicyClient
	n        int
	err      error
	setCalls int
}

func (w *iamSetErrorAfterN) GetIamPolicy(ctx context.Context, req *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	return w.inner.GetIamPolicy(ctx, req)
}

func (w *iamSetErrorAfterN) SetIamPolicy(ctx context.Context, req *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	w.setCalls++
	if w.setCalls > w.n {
		return nil, w.err
	}
	return w.inner.SetIamPolicy(ctx, req)
}

func TestGrantThenRead_GrantFailureBubblesUp(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	iam.getErr = errors.New("upstream 503")
	reader := &fakeRetryGetter{value: "v"}
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	_, err = mgr.GrantThenRead(context.Background(), "X")
	if err == nil {
		t.Fatal("expected error from grant phase")
	}
	if !strings.Contains(err.Error(), "temp grant add") {
		t.Errorf("err=%q want 'temp grant add' wrap", err.Error())
	}
	if reader.calls.Load() != 0 {
		t.Errorf("reader.calls=%d want 0 (no read attempted)", reader.calls.Load())
	}
}

func TestGrantingSrcReader_DelegatesToManager(t *testing.T) {
	iam := newFakeIAMPolicyClient()
	reader := &fakeRetryGetter{value: "hello"}
	mgr, err := newLiveTempGrantManager(iam, reader, "proj", "sa@x.iam", time.Minute)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	g := &grantingSrcReader{mgr: mgr}
	v, err := g.Get(context.Background(), "X")
	if err != nil || v != "hello" {
		t.Fatalf("Get=%q err=%v", v, err)
	}
}
