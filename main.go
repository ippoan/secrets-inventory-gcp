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
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type secretItem struct {
	Name      string            `json:"name"`
	CreatedAt string            `json:"created_at,omitempty"`
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

func newMuxWith(l secretLister, projectID, apiKey string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.Handle("/list-secrets", requireAPIKey(apiKey, handleListSecrets(l, projectID)))
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
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

		items := make([]secretItem, 0, len(secrets))
		for _, s := range secrets {
			items = append(items, secretItem{
				Name:      shortName(s.GetName()),
				CreatedAt: tsToRFC3339(s.GetCreateTime()),
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
