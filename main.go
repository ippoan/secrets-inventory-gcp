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
	"strings"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
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

	mux := newMuxWith(&liveLister{c: client}, projectID, apiKey)

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

func newMuxWith(l secretLister, projectID, apiKey string) *http.ServeMux {
	mux := http.NewServeMux()
	// `/healthz` は Cloud Run / GFE の reserved path 扱いで Google edge が直接
	// 404 HTML を返してしまう (実 staging で再現)。`/health` に rename して
	// app に届くようにする。
	mux.HandleFunc("/health", handleHealth)
	mux.Handle("/list-secrets", requireAPIKey(apiKey, handleListSecrets(l, projectID)))
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
