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

// --- Phase 3: Service Token create (Refs #42) ------------------------------

// cfServiceTokenCreateBody は worker → proxy の create request body。
// CF は token 名の一意性を保証しないので create は常に新規発行。
// `sm_secret_name` = 発行時に一度だけ返る client_secret の着地先。
type cfServiceTokenCreateBody struct {
	Name         string `json:"name"`
	Duration     string `json:"duration,omitempty"`
	SmSecretName string `json:"sm_secret_name"`
	FailIfExists bool   `json:"fail_if_exists"`
}

// cfRawServiceTokenCreate は CF create API の result。**client_secret は発行時
// のみ返る** (= 取りこぼすと再生成しかない)。
type cfRawServiceTokenCreate struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Duration     string `json:"duration,omitempty"`
}

// cfServiceTokenCreateResponse は worker に返す metadata。**client_secret は
// 含めない** (= proxy が SM に直書きし、値は LLM context / log に載らない)。
type cfServiceTokenCreateResponse struct {
	Ok           bool   `json:"ok"`
	TokenID      string `json:"token_id"`
	Name         string `json:"name,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	SmSecretName string `json:"sm_secret_name"`
	SmVersion    string `json:"sm_version"`
	Created      bool   `json:"created"`
}

// cfServiceTokenNameOK は CF service token 名の最小 validate。非空・長さ上限・
// 制御文字なし (= log injection 防止)。CF は名前に空白等を許すため charset は
// 広めに取り、厳格な命名規約 enforcement は worker 側に委ねる。
func cfServiceTokenNameOK(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// handleCfServiceTokenCreate は `POST /cf/service-tokens` のハンドラ。
//
// CF の `POST /accounts/{a}/access/service_tokens` を叩いて新規 token を発行
// させ、**発行時のみ返る client_secret を proxy memory 内で GCP Secret Manager
// の `sm_secret_name` に直書き**する (rotate と同経路)。client_secret は
// response / log に一切 echo しない。
func handleCfServiceTokenCreate(getter secretValueGetter, cfg cfConfig, http_ httpDoer, l secretLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body cfServiceTokenCreateBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if !cfServiceTokenNameOK(body.Name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		if body.SmSecretName == "" {
			http.Error(w, "sm_secret_name is required", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(body.SmSecretName) {
			http.Error(w, "invalid sm_secret_name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(body.Name)
		smName := sanitizeLogValue(body.SmSecretName)
		log.Printf("CF_SVCTOKEN_CREATE requested actor=%q name=%q sm_secret_name=%q fail_if_exists=%v",
			actor, target, smName, body.FailIfExists)

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_SVCTOKEN_CREATE token fetch failed name=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// CF create body。duration 省略時は CF default に委ねる (送らない)。
		reqBody := map[string]string{"name": body.Name}
		if body.Duration != "" {
			reqBody["duration"] = body.Duration
		}
		postBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			cfg.serviceTokensBase(), strings.NewReader(string(postBody)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_SVCTOKEN_CREATE upstream network name=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_SVCTOKEN_CREATE upstream %d name=%q", res.StatusCode, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		var env cfEnvelope[cfRawServiceTokenCreate]
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			log.Printf("CF_SVCTOKEN_CREATE decode name=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if !env.Success || env.Result.ClientSecret == "" || env.Result.ID == "" {
			log.Printf("CF_SVCTOKEN_CREATE bad envelope name=%q success=%v", target, env.Success)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// 新 client_secret を GCP SM へ。値は newSecret 内のみ、log / response に出さない。
		newSecret := env.Result.ClientSecret
		parent := fmt.Sprintf("projects/%s", projectID)
		secretFullName, alreadyExists, err := l.CreateSecret(ctx, parent, body.SmSecretName)
		if err != nil {
			log.Printf("CF_SVCTOKEN_CREATE sm create failed name=%q sm=%q err=%v", target, smName, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if alreadyExists && body.FailIfExists {
			log.Printf("CF_SVCTOKEN_CREATE sm conflict name=%q sm=%q", target, smName)
			http.Error(w, "sm secret already exists", http.StatusConflict)
			return
		}
		newVersionName, err := l.AddSecretVersion(ctx, secretFullName, []byte(newSecret))
		if err != nil {
			log.Printf("CF_SVCTOKEN_CREATE sm add-version failed name=%q sm=%q err=%v", target, smName, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("CF_SVCTOKEN_CREATE ok actor=%q name=%q token_id=%q sm=%q sm_version=%q created=%v",
			actor, target, sanitizeLogValue(env.Result.ID), smName, sanitizeLogValue(newVersionName), !alreadyExists)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfServiceTokenCreateResponse{
			Ok:           true,
			TokenID:      env.Result.ID,
			Name:         env.Result.Name,
			ClientID:     env.Result.ClientID,
			ExpiresAt:    env.Result.ExpiresAt,
			SmSecretName: body.SmSecretName,
			SmVersion:    newVersionName,
			Created:      !alreadyExists,
		})
	})
}

// --- Phase 2: Service Token rotate / delete (Refs #40) ---------------------

// cfServiceTokenRotateBody は worker → proxy の rotate request body。
// `sm_secret_name` = rotate で発行される新 client_secret を着地させる GCP SM
// short name (= cf_token_id ラベル台帳の保管先)。`fail_if_exists` は SM 側で
// 既存衝突時に 409 にするか (true) / 既存再利用で新 version 投入するか (false)。
type cfServiceTokenRotateBody struct {
	SmSecretName string `json:"sm_secret_name"`
	FailIfExists bool   `json:"fail_if_exists"`
}

// cfRawServiceTokenRotate は CF rotate API の result。create と同型で、
// **新 client_secret を発行時に一度だけ返す** (= 取りこぼすと再生成しかない)。
type cfRawServiceTokenRotate struct {
	ID                  string `json:"id"`
	ClientID            string `json:"client_id,omitempty"`
	ClientSecret        string `json:"client_secret,omitempty"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	ClientSecretVersion int    `json:"client_secret_version,omitempty"`
}

// cfServiceTokenRotateResponse は worker に返す metadata。**client_secret は
// 含めない** (= proxy が SM に直書きし、値は LLM context / log に載らない)。
type cfServiceTokenRotateResponse struct {
	Ok                  bool   `json:"ok"`
	TokenID             string `json:"token_id"`
	ClientID            string `json:"client_id,omitempty"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	ClientSecretVersion int    `json:"client_secret_version,omitempty"`
	SmSecretName        string `json:"sm_secret_name"`
	SmVersion           string `json:"sm_version"`
	Created             bool   `json:"created"`
}

type cfServiceTokenDeleteResponse struct {
	Ok      bool   `json:"ok"`
	TokenID string `json:"token_id"`
	// SmSecretName / LabelApplied は delete request に `sm_secret_name` query が
	// 渡された時だけ意味を持つ。LabelApplied は対象 SM secret に
	// `cf_service_token=deleted` audit label を打てたか (= revoke は成功した
	// が label patch が失敗した場合は false で返り、CF revoke 自体は ok)。
	SmSecretName string `json:"sm_secret_name,omitempty"`
	LabelApplied bool   `json:"label_applied,omitempty"`
}

// cfServiceTokenDeletedLabel は delete 時に SM secret (client_secret 保管先) へ
// 打つ audit label。台帳キー (`cf_token_id`) とは別に「この client_secret に
// 対応する CF service token は revoke 済み」を記録する。GCP label の制約
// (key/value とも lowercase 英数 + `_` `-`、63 文字以内、key 先頭は英字) を満たす。
const (
	cfServiceTokenDeletedLabelKey = "cf_service_token"
	cfServiceTokenDeletedLabelVal = "deleted"
)

// handleCfServiceTokenRotate は `POST /cf/service-tokens/{id}/rotate` のハンドラ。
//
// CF の `POST /accounts/{a}/access/service_tokens/{id}/rotate` を叩いて新しい
// client_secret を発行させ、**その値を proxy memory 内で GCP Secret Manager の
// `sm_secret_name` に書き込む** (`/create-secret` と同じ CreateSecret +
// AddSecretVersion 経路)。client_secret は response / log に **一切 echo
// しない**。返すのは metadata のみ。
//
// grace 期間 (無停止移行) は CF native 挙動に委ねる (= rotate 後の旧 secret の
// 失効タイミングは CF 側仕様。未確定 param は proxy で送らない)。
func handleCfServiceTokenRotate(getter secretValueGetter, cfg cfConfig, http_ httpDoer, l secretLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/cf/service-tokens/")
		id = strings.TrimSuffix(id, "/rotate")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if !cfSecretIDPattern.MatchString(id) {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}
		var body cfServiceTokenRotateBody
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if body.SmSecretName == "" {
			http.Error(w, "sm_secret_name is required", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(body.SmSecretName) {
			http.Error(w, "invalid sm_secret_name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(id)
		smName := sanitizeLogValue(body.SmSecretName)
		log.Printf("CF_SVCTOKEN_ROTATE requested actor=%q token_id=%q sm_secret_name=%q fail_if_exists=%v",
			actor, target, smName, body.FailIfExists)

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_SVCTOKEN_ROTATE token fetch failed token_id=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			cfg.serviceTokensBase()+"/"+id+"/rotate", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_SVCTOKEN_ROTATE upstream network token_id=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_SVCTOKEN_ROTATE upstream %d token_id=%q", res.StatusCode, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		var env cfEnvelope[cfRawServiceTokenRotate]
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			log.Printf("CF_SVCTOKEN_ROTATE decode token_id=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if !env.Success || env.Result.ClientSecret == "" {
			log.Printf("CF_SVCTOKEN_ROTATE bad envelope token_id=%q success=%v", target, env.Success)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// 新 client_secret を GCP SM へ。値は変数 newSecret 内のみで取り回し、
		// log / response に出さない (= /create-secret と同じ値非漏洩規約)。
		newSecret := env.Result.ClientSecret
		parent := fmt.Sprintf("projects/%s", projectID)
		secretFullName, alreadyExists, err := l.CreateSecret(ctx, parent, body.SmSecretName)
		if err != nil {
			log.Printf("CF_SVCTOKEN_ROTATE sm create failed token_id=%q sm=%q err=%v", target, smName, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if alreadyExists && body.FailIfExists {
			log.Printf("CF_SVCTOKEN_ROTATE sm conflict token_id=%q sm=%q", target, smName)
			http.Error(w, "sm secret already exists", http.StatusConflict)
			return
		}
		newVersionName, err := l.AddSecretVersion(ctx, secretFullName, []byte(newSecret))
		if err != nil {
			log.Printf("CF_SVCTOKEN_ROTATE sm add-version failed token_id=%q sm=%q err=%v", target, smName, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		log.Printf("CF_SVCTOKEN_ROTATE ok actor=%q token_id=%q sm=%q sm_version=%q created=%v",
			actor, target, smName, sanitizeLogValue(newVersionName), !alreadyExists)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfServiceTokenRotateResponse{
			Ok:                  true,
			TokenID:             id,
			ClientID:            env.Result.ClientID,
			ExpiresAt:           env.Result.ExpiresAt,
			ClientSecretVersion: env.Result.ClientSecretVersion,
			SmSecretName:        body.SmSecretName,
			SmVersion:           newVersionName,
			Created:             !alreadyExists,
		})
	})
}

// handleCfServiceTokenDelete は `DELETE /cf/service-tokens/{id}` のハンドラ。
// CF の `DELETE /accounts/{a}/access/service_tokens/{id}` を pass-through して
// 野良 token を revoke する。
//
// 任意 query `?sm_secret_name=<short>` を渡すと、revoke 成功後にその
// client_secret 保管 SM secret へ `cf_service_token=deleted` audit label を
// 打つ (= 台帳が空でも明示渡しで対象 secret を特定できる経路、Refs #68)。
// label patch は `secretsInventoryLabeler` 権限が要り、失敗しても CF revoke は
// 既に成立しているので fatal にせず response の `label_applied=false` で返す。
// 値 (client_secret) には触れない (= label メタデータのみ操作)。
func handleCfServiceTokenDelete(getter secretValueGetter, cfg cfConfig, http_ httpDoer, l secretLister, projectID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/cf/service-tokens/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if !cfSecretIDPattern.MatchString(id) {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		// optional sm_secret_name は CF revoke を打つ前に format 検証して、
		// 不正なら revoke せず 400 で返す (= revoke 成立後に 400 を返して
		// 副作用と応答が食い違う事故を防ぐ)。
		smName := r.URL.Query().Get("sm_secret_name")
		if smName != "" && !secretNamePattern.MatchString(smName) {
			http.Error(w, "invalid sm_secret_name", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		target := sanitizeLogValue(id)
		log.Printf("CF_SVCTOKEN_DELETE requested actor=%q token_id=%q sm_secret_name=%q",
			actor, target, sanitizeLogValue(smName))

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		token, err := getter.Get(ctx, cfg.tokenSecret)
		if err != nil {
			log.Printf("CF_SVCTOKEN_DELETE token fetch failed token_id=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
			cfg.serviceTokensBase()+"/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")

		res, err := http_.Do(req)
		if err != nil {
			log.Printf("CF_SVCTOKEN_DELETE upstream network token_id=%q err=%v", target, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("CF_SVCTOKEN_DELETE upstream %d token_id=%q", res.StatusCode, target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		// 2xx かつ envelope success=false は best-effort で弾く (delete は CF 側で
		// 成立していても envelope 不正なことがあるので 2xx を主、success を従に見る)。
		var env cfEnvelope[json.RawMessage]
		if err := json.NewDecoder(res.Body).Decode(&env); err == nil && !env.Success {
			log.Printf("CF_SVCTOKEN_DELETE envelope success=false token_id=%q", target)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}

		// revoke 成立後に audit label を打つ (best-effort)。失敗しても CF token
		// は既に revoke 済みなので 200 を返し、label_applied=false で伝える。
		labelApplied := false
		if smName != "" {
			secretFullName := fmt.Sprintf("projects/%s/secrets/%s", projectID, smName)
			if err := l.UpdateSecretLabels(ctx, secretFullName,
				map[string]string{cfServiceTokenDeletedLabelKey: cfServiceTokenDeletedLabelVal}); err != nil {
				log.Printf("CF_SVCTOKEN_DELETE label patch failed token_id=%q sm=%q err=%v",
					target, sanitizeLogValue(smName), err)
			} else {
				labelApplied = true
				log.Printf("CF_SVCTOKEN_DELETE label applied token_id=%q sm=%q %s=%s",
					target, sanitizeLogValue(smName), cfServiceTokenDeletedLabelKey, cfServiceTokenDeletedLabelVal)
			}
		}

		log.Printf("CF_SVCTOKEN_DELETE ok actor=%q token_id=%q label_applied=%v", actor, target, labelApplied)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfServiceTokenDeleteResponse{
			Ok:           true,
			TokenID:      id,
			SmSecretName: smName,
			LabelApplied: labelApplied,
		})
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
