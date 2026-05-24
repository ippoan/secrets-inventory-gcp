package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// secretValueGetter は GCP Secret Manager の **値 (payload)** を取り出す境界。
// `/cf/*` `/gh/*` handler 群が CF API token / GitHub PAT を runtime に取得する
// ために使う。`/list-secrets` 系の **メタデータ read** とは IAM スコープが異なる
// (`roles/secretmanager.secretAccessor` を per-secret に限定 grant する想定)
// ため、interface を分けて使い所を狭める。
//
// テストでは fakeSecretValueGetter を差し込んで Secret Manager call なしに
// 値を返す。
type secretValueGetter interface {
	// Get は `shortName` (= GCP Secret Manager の secret 短縮名) の latest
	// version payload を string で返す。Secret Manager は payload を []byte で
	// 返すが、proxy が扱う CF token / GitHub PAT は ASCII string なので
	// string に変換して返す。
	//
	// 値そのものは絶対に log / error message に echo しない。失敗時は upstream
	// error を generic に wrap して返す。
	Get(ctx context.Context, shortName string) (string, error)
}

// liveSecretValueGetter は Secret Manager の AccessSecretVersion を直接叩く
// production 実装。`projectID` + short name から full version name を組み立て
// `latest` alias を使う。
type liveSecretValueGetter struct {
	client    *secretmanager.Client
	projectID string
}

func (g *liveSecretValueGetter) Get(ctx context.Context, shortName string) (string, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", g.projectID, shortName)
	resp, err := g.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return "", err
	}
	payload := resp.GetPayload()
	if payload == nil {
		return "", fmt.Errorf("secret %s has empty payload", shortName)
	}
	return string(payload.GetData()), nil
}

// cachedSecretValueGetter は別 getter を TTL cache で wrap する。
//
// 用途:
//   - 1 request あたり最大 2 token (CF + GH) を Secret Manager から取るが
//     rotate 一発で複数 endpoint が叩かれるとあっという間に API call が増える
//   - 同じ secret を高頻度に access することで audit log が騒がしくなる
//
// 5 分 TTL なら rotate 直後の伝播 lag が最大 5 分。rotate は人間操作で
// 数分以内に follow-up rotation が走る運用ではないので acceptable。
//
// rotate が起きた瞬間に invalidate するための明示的 API は持たない (= proxy
// 単体で完結する最小実装)。
type cachedSecretValueGetter struct {
	inner secretValueGetter
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cachedEntry
}

type cachedEntry struct {
	value     string
	expiresAt time.Time
}

func newCachedSecretValueGetter(inner secretValueGetter, ttl time.Duration) *cachedSecretValueGetter {
	return &cachedSecretValueGetter{
		inner: inner,
		ttl:   ttl,
		now:   time.Now,
		cache: map[string]cachedEntry{},
	}
}

func (g *cachedSecretValueGetter) Get(ctx context.Context, shortName string) (string, error) {
	now := g.now()
	g.mu.Lock()
	entry, ok := g.cache[shortName]
	g.mu.Unlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.value, nil
	}

	// cache miss / expired: upstream に問い合わせる。並行で同じ secret が来ても
	// 二重 fetch する程度の race は許容 (= cache stampede 対策はしない、N=2 だし)。
	v, err := g.inner.Get(ctx, shortName)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	g.cache[shortName] = cachedEntry{value: v, expiresAt: now.Add(g.ttl)}
	g.mu.Unlock()
	return v, nil
}
