package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GitHub Actions **repo variables** proxy (Refs ippoan/secrets-inventory#45 系)。
//
// `/gh/secrets` が org secret を libsodium sealed box で暗号化して扱うのに対し、
// こちらは repo-level の **平文 config 値** (= GitHub Actions Variables) を扱う。
// secret ではないので暗号化せず素の value で POST/PATCH する。値は config として
// list で読めてよい (= secret と違い隠さない) が、log には value を出さない。
//
//   - GET /gh/variables?repo={owner}/{repo}        — repo variables list (value 含む)
//   - PUT /gh/variables/{name}?repo={owner}/{repo} — upsert (無ければ POST=create、有れば PATCH=update)
//
// 認証 token は ghConfig.token() を流用する (App installation token は owner=org
// 単位で発行され、その org 配下の repo にそのまま使える)。owner を org として
// cfg.resolve() に通すことで PAT allowlist / App mode の判定も /gh/secrets と共有する。

// ghRepoNamePattern は GitHub repo 名 (owner を除いた部分) の制約。
// 英数字 + `.` `_` `-`、1..=100 文字 (GitHub の repo 名規約に概ね一致)。
var ghRepoNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// ghVarPutBody は PUT body。`value` は平文 (= variables は secret ではない)。
type ghVarPutBody struct {
	Value string `json:"value"`
}

// ghVarPutResponse の `created` は GET での存在確認に基づく権威ある値:
// 事前 GET が 404 → POST (create) → created=true、200 → PATCH (update) → created=false。
type ghVarPutResponse struct {
	Ok      bool `json:"ok"`
	Created bool `json:"created"`
}

type ghRawVariable struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ghVariablesAPIResponse struct {
	TotalCount int             `json:"total_count"`
	Variables  []ghRawVariable `json:"variables"`
}

type ghVariablesListResponse struct {
	Variables []ghRawVariable `json:"variables"`
}

// parseGhRepoParam は `?repo=owner/name` を検証して (owner, repo) に分解する。
func parseGhRepoParam(raw string) (owner, repo string, err error) {
	owner, repo, found := strings.Cut(raw, "/")
	if !found {
		return "", "", fmt.Errorf("repo must be owner/name")
	}
	if !ghOrgPattern.MatchString(owner) {
		return "", "", fmt.Errorf("invalid owner")
	}
	if !ghRepoNamePattern.MatchString(repo) {
		return "", "", fmt.Errorf("invalid repo")
	}
	return owner, repo, nil
}

// newGhRequest は GitHub API 用の共通ヘッダを載せた request を組む。
func newGhRequest(ctx context.Context, method, url, token string, body io.Reader) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, method, url, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "secrets-inventory-gcp")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// handleGhVariablesList は `GET /gh/variables?repo={owner}/{repo}` のハンドラ。
func handleGhVariablesList(getter secretValueGetter, cfg ghConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		owner, repo, err := parseGhRepoParam(r.URL.Query().Get("repo"))
		if err != nil {
			log.Printf("GH_VAR_LIST repo rejected: %v", err)
			http.Error(w, "invalid repo", http.StatusBadRequest)
			return
		}
		resolved, err := cfg.resolve(owner)
		if err != nil {
			log.Printf("GH_VAR_LIST org rejected: %v", err)
			http.Error(w, "org not allowed", http.StatusBadRequest)
			return
		}
		cfg = resolved

		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		token, err := cfg.token(ctx, getter, http_)
		if err != nil {
			log.Printf("GH_VAR_LIST token fetch failed: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		out := []ghRawVariable{}
		page := 1
		for ; page <= 100; page++ {
			url := fmt.Sprintf("%s/repos/%s/%s/actions/variables?per_page=100&page=%d",
				githubAPI, owner, repo, page)
			res, err := http_.Do(newGhRequest(ctx, http.MethodGet, url, token, nil))
			if err != nil {
				log.Printf("GH_VAR_LIST upstream network page=%d: %v", page, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			if res.StatusCode/100 != 2 {
				res.Body.Close()
				log.Printf("GH_VAR_LIST upstream %d page=%d", res.StatusCode, page)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			var resp ghVariablesAPIResponse
			if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
				res.Body.Close()
				log.Printf("GH_VAR_LIST decode page=%d: %v", page, err)
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			res.Body.Close()
			out = append(out, resp.Variables...)
			if len(resp.Variables) < 100 {
				break
			}
		}
		if page > 100 {
			log.Printf("GH_VAR_LIST pagination exceeded 100 pages")
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ghVariablesListResponse{Variables: out})
	})
}

// handleGhVariablePut は `PUT /gh/variables/{name}?repo={owner}/{repo}` のハンドラ。
// 事前 GET で存在確認し、無ければ POST (create)、有れば PATCH (update) する。
// value は平文だが log には出さない (value_bytes のみ)。
func handleGhVariablePut(getter secretValueGetter, cfg ghConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/gh/variables/")
		if name == "" || strings.Contains(name, "/") {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		owner, repo, err := parseGhRepoParam(r.URL.Query().Get("repo"))
		if err != nil {
			log.Printf("GH_VAR_PUT repo rejected: %v", err)
			http.Error(w, "invalid repo", http.StatusBadRequest)
			return
		}
		resolved, err := cfg.resolve(owner)
		if err != nil {
			log.Printf("GH_VAR_PUT org rejected: %v", err)
			http.Error(w, "org not allowed", http.StatusBadRequest)
			return
		}
		cfg = resolved

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(name)

		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body ghVarPutBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if body.Value == "" {
			http.Error(w, "value is required", http.StatusBadRequest)
			return
		}
		if len(body.Value) > maxSecretValueBytes {
			http.Error(w, "value too large", http.StatusBadRequest)
			return
		}

		log.Printf("GH_VAR_PUT requested actor=%q owner=%q repo=%q target=%q value_bytes=%d",
			actor, sanitizeLogValue(owner), sanitizeLogValue(repo), target, len(body.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		token, err := cfg.token(ctx, getter, http_)
		if err != nil {
			log.Printf("GH_VAR_PUT token fetch failed actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// 存在確認 → create (POST) / update (PATCH) を決める
		getURL := fmt.Sprintf("%s/repos/%s/%s/actions/variables/%s", githubAPI, owner, repo, name)
		getRes, err := http_.Do(newGhRequest(ctx, http.MethodGet, getURL, token, nil))
		if err != nil {
			log.Printf("GH_VAR_PUT existence-check network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		getRes.Body.Close()
		exists := getRes.StatusCode == http.StatusOK
		if !exists && getRes.StatusCode != http.StatusNotFound {
			log.Printf("GH_VAR_PUT existence-check upstream %d actor=%q target=%q",
				getRes.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		payload, _ := json.Marshal(struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}{Name: name, Value: body.Value})

		var method, writeURL string
		if exists {
			method = http.MethodPatch
			writeURL = fmt.Sprintf("%s/repos/%s/%s/actions/variables/%s", githubAPI, owner, repo, name)
		} else {
			method = http.MethodPost
			writeURL = fmt.Sprintf("%s/repos/%s/%s/actions/variables", githubAPI, owner, repo)
		}
		writeRes, err := http_.Do(newGhRequest(ctx, method, writeURL, token, strings.NewReader(string(payload))))
		if err != nil {
			log.Printf("GH_VAR_PUT upstream network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer writeRes.Body.Close()
		// POST create → 201 Created、PATCH update → 204 No Content
		if writeRes.StatusCode != http.StatusCreated && writeRes.StatusCode != http.StatusNoContent {
			log.Printf("GH_VAR_PUT upstream %d actor=%q target=%q", writeRes.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("GH_VAR_PUT ok actor=%q owner=%q repo=%q target=%q created=%v",
			actor, sanitizeLogValue(owner), sanitizeLogValue(repo), target, !exists)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ghVarPutResponse{Ok: true, Created: !exists})
	})
}
