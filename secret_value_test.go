package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSecretValueGetter は secretValueGetter の test 用 fake。`values` に
// 入れた key → value を返し、`err` non-nil なら常に error。
// `calls` は呼び出し回数を counts する (= cache が効いているか観測用)。
type fakeSecretValueGetter struct {
	values map[string]string
	err    error
	calls  atomic.Int32
}

func (f *fakeSecretValueGetter) Get(_ context.Context, shortName string) (string, error) {
	f.calls.Add(1)
	if f.err != nil {
		return "", f.err
	}
	if f.values == nil {
		return "", nil
	}
	v, ok := f.values[shortName]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func TestCachedSecretValueGetter_CachesWithinTTL(t *testing.T) {
	inner := &fakeSecretValueGetter{values: map[string]string{"foo": "bar"}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCachedSecretValueGetter(inner, 5*time.Minute)
	c.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		v, err := c.Get(context.Background(), "foo")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if v != "bar" {
			t.Fatalf("got %q", v)
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("expected 1 upstream call, got %d", got)
	}
}

func TestCachedSecretValueGetter_ExpiresAfterTTL(t *testing.T) {
	inner := &fakeSecretValueGetter{values: map[string]string{"foo": "bar"}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newCachedSecretValueGetter(inner, 5*time.Minute)
	current := now
	c.now = func() time.Time { return current }

	if _, err := c.Get(context.Background(), "foo"); err != nil {
		t.Fatal(err)
	}
	current = now.Add(6 * time.Minute)
	if _, err := c.Get(context.Background(), "foo"); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Errorf("expected 2 upstream calls after TTL expiry, got %d", got)
	}
}

func TestCachedSecretValueGetter_PropagatesError(t *testing.T) {
	inner := &fakeSecretValueGetter{err: errors.New("boom")}
	c := newCachedSecretValueGetter(inner, time.Minute)
	if _, err := c.Get(context.Background(), "foo"); err == nil {
		t.Error("expected error from inner")
	}
}
