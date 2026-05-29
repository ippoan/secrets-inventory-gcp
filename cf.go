package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// CF Secrets Store proxy endpoints。worker (`secrets-inventory`) が直接
// Cloudflare API を叩くのを廃止し、本 proxy 経由で `GCP_PROXY_API_KEY` 1 個
// だけ持てば済むようにする。Refs ippoan/secrets-inventory#45.
//
// 提供 endpoint:
//   - `GET  /cf/secrets`        — list (inventory + create 前の存在チェック)
//   - `POST /cf/secrets/{id}`   — value 更新 (= rotate)
//   - `POST /cf/secrets`        — create (新規 secret + 初版投入)
//
// CF API token は Secret Manager から runtime 取得 (= worker 側に持たない)。
// 値は body の `value` field でのみ運び、log / response に echo しない。

const cfAPI = "https://api.cloudflare.com/client/v4"

// cfRotateBody / cfCreateBody は POST body。`value` は **JSON body のみ**
// (= header / query に出ない)。
type cfRotateBody struct {
	Value string `json:"value"`
}

type cfCreateBody struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Scopes []string `json:"scopes,omitempty"`
}

// cfRawSecret は Cloudflare API の Secrets Store secret 1 件 (list 用)。
type cfRawSecret struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Comment  string   `json:"comment,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Status   string   `json:"status,omitempty"`
	Created  string   `json:"created,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

type cfEnvelope[T any] struct {
	Success bool     `json:"success"`
	Result  T        `json:"result"`
	Errors  []cfErr  `json:"errors,omitempty"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfListResponse は worker 側にそのまま返す list response。
// `secrets-inventory` worker の SecretMetadata に近い shape を保つ。
type cfListResponse struct {
	Secrets []cfSecretView `json:"secrets"`
}

type cfSecretView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Comment  string   `json:"comment,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Status   string   `json:"status,omitempty"`
	Created  string   `json:"created,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

type cfRotateResponse struct {
	Ok       bool   `json:"ok"`
	SecretID string `json:"secret_id"`
}

type cfCreateResponse struct {
	Ok       bool   `json:"ok"`
	SecretID string `json:"secret_id"`
	Name     string `json:"name"`
}

// cfConfig は CF endpoint 群が共有する設定。`accountID` / `storeID` は env
// 由来の定数、`tokenSecret` は Secret Manager 上の token を指す short name。
//
// 3 field が **すべて** non-empty なら configured。1 つでも空なら未設定扱いで
// handler が 503 を返す (= 運用 setup と code deploy を分離するため)。
type cfConfig struct {
	accountID   string
	storeID     string
	tokenSecret string
}

func (c cfConfig) configured() bool {
	return c.accountID != "" && c.storeID != "" && c.tokenSecret != ""
}

// cfBase は `/accounts/{a}/secrets_store/stores/{s}/secrets` のベース URL を
// 組み立てる。worker 側の cloudflare.ts と同 path。
func (c cfConfig) base() string {
	return fmt.Sprintf("%s/accounts/%s/secrets_store/stores/%s/secrets", cfAPI, c.accountID, c.storeID)
}

// serviceTokensBase は CF Access Service Token list の base URL を組み立てる。
// Secrets Store とは **別 API** (`access/service_tokens`) で account 直下、
// `storeID` は使わない (Refs #38)。
func (c cfConfig) serviceTokensBase() string {
	return fmt.Sprintf("%s/accounts/%s/access/service_tokens", cfAPI, c.accountID)
}

// cfRawServiceToken は Cloudflare Access の Service Token 1 件 (list 用)。
// `client_secret` は list では **構造的に返らない** (= 値非漏洩) ので持たない。
// CF API は時刻を `created_at` / `updated_at` で返す (Secrets Store の
// `created` / `modified` とは field 名が違う)。
type cfRawServiceToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ClientID  string `json:"client_id,omitempty"`
	Duration  string `json:"duration,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// cfServiceTokenView は worker にそのまま返す view。時刻は `created` /
// `modified` に正規化して `cfSecretView` と shape を揃え、worker の
// `SecretMetadata` への map を容易にする。`client_id` / `duration` は
// worker 側で `extra` に載せる用 (= 突合キー候補 / 期限把握)。
type cfServiceTokenView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id,omitempty"`
	Duration string `json:"duration,omitempty"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
}

// cfServiceTokenListResponse は `GET /cf/service-tokens` の response。
type cfServiceTokenListResponse struct {
	ServiceTokens []cfServiceTokenView `json:"service_tokens"`
}

// handleCfServiceTokenList は `GET /cf/service-tokens` のハンドラ。
// CF Access の `GET /accounts/{a}/access/service_tokens?per_page=100` を
// 1 回叩いて返す (`handleCfList` とほぼ同型)。list は `client_secret` を
// 返さない API なので値非漏洩の追加対応は不要。MVP は read のみ
// (rotate/delete/create は Phase 2/3・別 issue)。Refs #38.
func handleCfServiceTokenList(getter secretValueGetter, cfg cfConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_SVCTOKEN_LIST token fetch failed: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.serviceTokensBase()+"?per_page=100", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_SVCTOKEN_LIST upstream network: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_SVCTOKEN_LIST upstream %d", res.StatusCode)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		var env cfEnvelope[[]cfRawServiceToken]
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			log.Printf("CF_SVCTOKEN_LIST decode: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if !env.Success {
			log.Printf("CF_SVCTOKEN_LIST success=false: %v", env.Errors)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		out := make([]cfServiceTokenView, 0, len(env.Result))
		for _, s := range env.Result {
			out = append(out, cfServiceTokenView{
				ID:       s.ID,
				Name:     s.Name,
				ClientID: s.ClientID,
				Duration: s.Duration,
				Created:  s.CreatedAt,
				Modified: s.UpdatedAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfServiceTokenListResponse{ServiceTokens: out})
	})
}

// handleCfList は `GET /cf/secrets` のハンドラ。
// Cloudflare API の list を per_page=100 (CF Secrets Store の上限) で 1 回
// 叩いて返す。実運用の secret 数は数十なので 100 で十分、pagination 不要。
// `per_page=1000` は `invalid_per_page_parameter` (code 1001) で 400 になる。
// 値そのものは API がそもそも返さない。
func handleCfList(getter secretValueGetter, cfg cfConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_LIST token fetch failed: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.base()+"?per_page=100", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_LIST upstream network: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_LIST upstream %d", res.StatusCode)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		var env cfEnvelope[[]cfRawSecret]
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			log.Printf("CF_LIST decode: %v", err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if !env.Success {
			log.Printf("CF_LIST success=false: %v", env.Errors)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		out := make([]cfSecretView, 0, len(env.Result))
		for _, s := range env.Result {
			out = append(out, cfSecretView{
				ID:       s.ID,
				Name:     s.Name,
				Comment:  s.Comment,
				Scopes:   s.Scopes,
				Status:   s.Status,
				Created:  s.Created,
				Modified: s.Modified,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfListResponse{Secrets: out})
	})
}

// cfSecretIDPattern は path から取る `{id}` の最小 validate。CF Secrets Store
// の id は UUID-ish (lowercase hex + hyphen) で観測される。`/` 等 path
// injection 文字は弾く。
var cfSecretIDPattern = mustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// handleCfRotate は `POST /cf/secrets/{id}` のハンドラ。CF API の
// `PATCH /accounts/.../secrets_store/stores/.../secrets/{id}` を呼んで
// 値を更新する (= 既存 secret の rotation)。
//
// 内部 PATCH を **POST** で expose する: worker 側の routing 制約 (= REST
// purity より consistency 優先) で、proxy への write は POST に統一。
// idempotency-key は持たない (= rotate は本質的に冪等でない、TOCTOU は
// CF API 側にも提供されていないので best effort)。
func handleCfRotate(getter secretValueGetter, cfg cfConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/cf/secrets/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if !cfSecretIDPattern.MatchString(id) {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(id)

		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body cfRotateBody
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

		log.Printf("CF_ROTATE requested actor=%q target=%q value_bytes=%d",
			actor, target, len(body.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_ROTATE token fetch failed actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		patchBody, _ := json.Marshal(struct {
			Value string `json:"value"`
		}{Value: body.Value})

		req, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
			cfg.base()+"/"+id, strings.NewReader(string(patchBody)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_ROTATE upstream network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_ROTATE upstream %d actor=%q target=%q", res.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		// PATCH response の success=true は best-effort で見る (2xx かつ envelope 不正
		// でも更新は成立する CF API の挙動に頑健に)。
		var env cfEnvelope[json.RawMessage]
		if err := json.NewDecoder(res.Body).Decode(&env); err == nil && !env.Success {
			log.Printf("CF_ROTATE envelope success=false actor=%q target=%q", actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("CF_ROTATE ok actor=%q target=%q", actor, target)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfRotateResponse{Ok: true, SecretID: id})
	})
}

// handleCfCreate は `POST /cf/secrets` のハンドラ。CF API の
// `POST /accounts/.../secrets_store/stores/.../secrets` を呼んで新規 secret
// を作成する。`fail_if_exists` semantics (= 既存 name 衝突を 409) は
// worker (caller) 側で list-then-create で実装する想定 (= proxy はシンプル
// POST だけを提供)。
//
// 命名は `secretNamePattern` を流用 (= /add-version / /create-secret と同じ
// 検証規則)。
func handleCfCreate(getter secretValueGetter, cfg cfConfig, http_ httpDoer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))

		r.Body = http.MaxBytesReader(w, r.Body, maxSecretValueBytes+1024)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body cfCreateBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(body.Name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
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

		target := sanitizeLogValue(body.Name)
		log.Printf("CF_CREATE requested actor=%q target=%q value_bytes=%d",
			actor, target, len(body.Value))

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_CREATE token fetch failed actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// CF API は POST body の scopes を必須としない (default `[]`) が、
		// worker から使う前提では `["workers"]` が安全な default。
		scopes := body.Scopes
		if len(scopes) == 0 {
			scopes = []string{"workers"}
		}
		// CF Secrets Store API は POST body を **array of secret objects** で
		// 期待する仕様 (https://developers.cloudflare.com/api/resources/
		// secrets_store/subresources/stores/subresources/secrets/methods/create/)。
		// 単体 object を送ると 400 "Bad Request" になる (Refs #31)。
		// 本 proxy は 1 secret ずつしか create しないので 1 要素の array で
		// 包む。scopes は worker 用 default `["workers"]`。
		postBody, _ := json.Marshal([]struct {
			Name   string   `json:"name"`
			Value  string   `json:"value"`
			Scopes []string `json:"scopes"`
		}{{Name: body.Name, Value: body.Value, Scopes: scopes}})

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			cfg.base(), strings.NewReader(string(postBody)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_CREATE upstream network actor=%q target=%q err=%v", actor, target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_CREATE upstream %d actor=%q target=%q", res.StatusCode, actor, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// CF API は単体 / 配列 (1 要素) のどちらでも result を返してくることが
		// あるので両 shape を try する。`id` が抜けていれば error。
		var single cfEnvelope[cfRawSecret]
		raw, _ := io.ReadAll(res.Body)
		if err := json.Unmarshal(raw, &single); err == nil && single.Success && single.Result.ID != "" {
			log.Printf("CF_CREATE ok actor=%q target=%q secret_id=%q",
				actor, target, sanitizeLogValue(single.Result.ID))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfCreateResponse{Ok: true, SecretID: single.Result.ID, Name: body.Name})
			return
		}
		var arr cfEnvelope[[]cfRawSecret]
		if err := json.Unmarshal(raw, &arr); err == nil && arr.Success && len(arr.Result) > 0 && arr.Result[0].ID != "" {
			log.Printf("CF_CREATE ok actor=%q target=%q secret_id=%q",
				actor, target, sanitizeLogValue(arr.Result[0].ID))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfCreateResponse{Ok: true, SecretID: arr.Result[0].ID, Name: body.Name})
			return
		}
		log.Printf("CF_CREATE bad envelope actor=%q target=%q", actor, target)
		http.Error(w, "upstream error", http.StatusBadGateway)
	})
}
