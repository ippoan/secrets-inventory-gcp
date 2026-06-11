package main

import (
	cloudrunproxy "github.com/ippoan/go-cloudrun-proxy"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// `POST /sync-from-gcp/{src_name}?targets=gh,cf&gh_name=NAME&cf_name=name`
//
// GCP Secret Manager に既にある secret の値を、CF Secrets Store / GitHub
// Actions org secrets に伝播させる endpoint。Refs ippoan/auth-worker#209
// PR4 (HEALTH_OAUTH_JWT を mint 後に CI から使えるようにする)。
//
// 値の物理経路:
//   GCP Secret Manager → AccessSecretVersion → proxy memory → {CF API, GitHub API}
//
// 呼び出し元 (worker) も LLM context も値を一度も見ない。proxy 内で完結。
//
// Query:
//   - targets   = "gh", "cf", "gh,cf" のいずれか (必須)
//   - gh_name   = GitHub Actions secret 名 (省略時 src_name)
//   - cf_name   = CF Secrets Store 名 (省略時 src_name)
//   - visibility= GitHub visibility (省略時 "all")
//   - scopes    = CF scope CSV (省略時 "workers")
//   - fail_if_exists = "true" (default) / "false"
//
// 既存 `/gh/secrets/{name}` と `/cf/secrets` の write logic を helper として
// extract したものを再利用する (= sealed-box encrypt + GitHub PUT、CF API
// POST or PATCH) 。重複 logic は putGhSecretWithValue / upsertCfSecretWithValue
// が担う。
//
// 必要 IAM (source secret read):
//   - srcGetter が tempGrantManager 経由 (liveTempGrantManager) の場合、
//     runtime SA は custom role `secretsInventoryTempAccessor`
//     (getIamPolicy + setIamPolicy) を持てば足り、各 source secret 単位の
//     accessor 事前 grant は **不要** (Refs #35)。temp grant が条件付きで
//     accessor を自動付与する。
//   - srcGetter が直接 secretValueGetter の場合 (= runtime SA email を
//     proxy が解決できない fallback path)、従来通り operator が per-secret
//     `roles/secretmanager.secretAccessor` を事前 grant する必要がある。
//     未 grant なら AccessSecretVersion で PermissionDenied → 502。

type syncTargetResult struct {
	Status     string `json:"status"`          // "ok" | "fail"
	Error      string `json:"error,omitempty"` // status=fail のときのみ
	SecretName string `json:"secret_name,omitempty"`
	SecretID   string `json:"secret_id,omitempty"` // CF のみ
	Created    bool   `json:"created,omitempty"`
}

type syncFromGcpResponse struct {
	Ok      bool                        `json:"ok"`
	Source  string                      `json:"source"`
	Results map[string]syncTargetResult `json:"results"`
}

// handleSyncFromGcp は sync handler を返す。
//
//   - getter:    CF / GH proxy token 等の **既に per-secret accessor が
//     permanent grant 済の secret** を読む。propagateToGh/Cf 内で
//     cfg.tokenSecret を取るのに使う。
//   - srcGetter: 本 endpoint の **source secret** (= sync 対象) を読む。
//     temp grant 経路 (grantingSrcReader) または直接 getter のどちらか。
//     nil なら getter にフォールバックして従来挙動 (= operator が
//     事前 gcloud grant した secret しか sync できない)。
func handleSyncFromGcp(
	getter secretValueGetter,
	srcGetter secretValueGetter,
	cfCfg cfConfig,
	ghCfg ghConfig,
	httpClient httpDoer,
) http.Handler {
	if srcGetter == nil {
		srcGetter = getter
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srcName := strings.TrimPrefix(r.URL.Path, "/sync-from-gcp/")
		if srcName == "" || strings.Contains(srcName, "/") {
			http.Error(w, "missing src_name", http.StatusBadRequest)
			return
		}
		if !secretNamePattern.MatchString(srcName) {
			http.Error(w, "invalid src_name", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()
		rawTargets := strings.TrimSpace(q.Get("targets"))
		if rawTargets == "" {
			http.Error(w, "targets is required (gh / cf / gh,cf)", http.StatusBadRequest)
			return
		}
		wantGh, wantCf := false, false
		for _, t := range strings.Split(rawTargets, ",") {
			switch strings.TrimSpace(t) {
			case "gh":
				wantGh = true
			case "cf":
				wantCf = true
			case "":
				// trailing comma, skip
			default:
				http.Error(w, "invalid targets (only gh/cf allowed)", http.StatusBadRequest)
				return
			}
		}
		if !wantGh && !wantCf {
			http.Error(w, "targets must include at least one of gh,cf", http.StatusBadRequest)
			return
		}
		// configured() guard: target を指定したのに env 未設定なら早期に reject。
		if wantGh && !ghCfg.configured() {
			http.Error(w, "gh target requested but GitHub config is missing", http.StatusServiceUnavailable)
			return
		}
		if wantCf && !cfCfg.configured() {
			http.Error(w, "cf target requested but Cloudflare config is missing", http.StatusServiceUnavailable)
			return
		}

		// `?gh_org=` で allowlist (GH_EXTRA_ORGS) 内の別 org に伝播できる
		// (Refs #49)。空なら従来どおり default org (GITHUB_ORG)。
		ghOrg := q.Get("gh_org")
		if ghOrg != "" && !wantGh {
			http.Error(w, "gh_org requires targets to include gh", http.StatusBadRequest)
			return
		}
		effGhCfg := ghCfg
		if wantGh {
			resolved, err := ghCfg.resolve(ghOrg)
			if err != nil {
				log.Printf("SYNC_FROM_GCP gh_org rejected: %v", err)
				http.Error(w, "gh_org not allowed", http.StatusBadRequest)
				return
			}
			effGhCfg = resolved
		}

		ghName := q.Get("gh_name")
		if ghName == "" {
			ghName = srcName
		}
		cfName := q.Get("cf_name")
		if cfName == "" {
			cfName = srcName
		}
		if wantGh && !secretNamePattern.MatchString(ghName) {
			http.Error(w, "invalid gh_name", http.StatusBadRequest)
			return
		}
		if wantCf && !secretNamePattern.MatchString(cfName) {
			http.Error(w, "invalid cf_name", http.StatusBadRequest)
			return
		}

		visibility := q.Get("visibility")
		if visibility == "" {
			visibility = "all"
		}
		switch visibility {
		case "all", "private", "selected":
		default:
			http.Error(w, "invalid visibility", http.StatusBadRequest)
			return
		}

		scopes := parseCsvQuery(q.Get("scopes"))
		if len(scopes) == 0 {
			scopes = []string{"workers"}
		}

		failIfExists := true
		switch strings.ToLower(q.Get("fail_if_exists")) {
		case "", "true", "1", "yes":
			failIfExists = true
		case "false", "0", "no":
			failIfExists = false
		default:
			http.Error(w, "invalid fail_if_exists", http.StatusBadRequest)
			return
		}

		actor := sanitizeLogValue(r.Header.Get("X-Actor-Email"))
		source := sanitizeLogValue(srcName)
		log.Printf("SYNC_FROM_GCP requested actor=%q source=%q targets=%q gh_org=%q gh_name=%q cf_name=%q",
			actor, source, sanitizeLogValue(rawTargets),
			sanitizeLogValue(effGhCfg.org), sanitizeLogValue(ghName), sanitizeLogValue(cfName))

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// 1. Read source value from GCP。
		// srcGetter が grantingSrcReader なら ここで自動的に conditional
		// binding が add される (TTL ≤ 10 分、defer cleanup)。直接 getter
		// なら従来通り永続 grant 前提で読む。
		value, err := srcGetter.Get(ctx, srcName)
		if err != nil {
			log.Printf("SYNC_FROM_GCP source read failed actor=%q source=%q err=%v",
				actor, source, err)
			http.Error(w, "upstream error (gcp read)", cloudrunproxy.StatusFromGRPC(err))
			return
		}
		if value == "" {
			log.Printf("SYNC_FROM_GCP source payload empty actor=%q source=%q", actor, source)
			http.Error(w, "upstream error (empty source)", http.StatusBadGateway)
			return
		}

		results := map[string]syncTargetResult{}
		ok := true

		if wantGh {
			r := propagateToGh(ctx, ghName, value, visibility, failIfExists,
				effGhCfg, getter, httpClient, actor)
			results["gh"] = r
			if r.Status != "ok" {
				ok = false
			}
		}
		if wantCf {
			r := propagateToCf(ctx, cfName, value, scopes, failIfExists,
				cfCfg, getter, httpClient, actor)
			results["cf"] = r
			if r.Status != "ok" {
				ok = false
			}
		}

		// value はここで scope を抜けるので Go GC に任せる (途中で zeroize する
		// 標準 API は無い)。
		_ = value

		log.Printf("SYNC_FROM_GCP done actor=%q source=%q ok=%v", actor, source, ok)
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		if !ok {
			status = http.StatusBadGateway
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(syncFromGcpResponse{
			Ok:      ok,
			Source:  srcName,
			Results: results,
		})
	})
}

// propagateToGh は handleGhPut の内側 logic を value 引数化したもの。
// CF と並走させるため failure は status="fail" + error を返す pattern にし
// HTTP response は呼び元 (handleSyncFromGcp) で組み立てる。
func propagateToGh(
	ctx context.Context,
	name, value, visibility string,
	failIfExists bool,
	cfg ghConfig,
	getter secretValueGetter,
	http_ httpDoer,
	actor string,
) syncTargetResult {
	target := sanitizeLogValue(name)
	token, err := getter.Get(ctx, cfg.tokenSecret)
	if err != nil {
		log.Printf("SYNC_GH token fetch failed actor=%q target=%q err=%v", actor, target, err)
		return syncTargetResult{Status: "fail", Error: "gh token fetch"}
	}

	// existence check (fail_if_exists=true のみ)
	if failIfExists {
		urlExist := fmt.Sprintf("%s/orgs/%s/actions/secrets/%s", githubAPI, cfg.org, name)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlExist, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")
		res, err := http_.Do(req)
		if err != nil {
			log.Printf("SYNC_GH existence-check network actor=%q target=%q err=%v",
				actor, target, err)
			return syncTargetResult{Status: "fail", Error: "gh existence-check network"}
		}
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			log.Printf("SYNC_GH conflict actor=%q target=%q already exists", actor, target)
			return syncTargetResult{Status: "fail", Error: "gh secret already exists"}
		}
		if res.StatusCode != http.StatusNotFound {
			log.Printf("SYNC_GH existence-check upstream %d actor=%q target=%q",
				res.StatusCode, actor, target)
			return syncTargetResult{Status: "fail", Error: "gh existence-check upstream"}
		}
	}

	pkURL := fmt.Sprintf("%s/orgs/%s/actions/secrets/public-key", githubAPI, cfg.org)
	pkReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, pkURL, nil)
	pkReq.Header.Set("Authorization", "Bearer "+token)
	pkReq.Header.Set("Accept", "application/vnd.github+json")
	pkReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	pkReq.Header.Set("User-Agent", "secrets-inventory-gcp")
	pkRes, err := http_.Do(pkReq)
	if err != nil {
		log.Printf("SYNC_GH public-key network actor=%q target=%q err=%v",
			actor, target, err)
		return syncTargetResult{Status: "fail", Error: "gh public-key network"}
	}
	if pkRes.StatusCode/100 != 2 {
		pkRes.Body.Close()
		log.Printf("SYNC_GH public-key upstream %d actor=%q target=%q",
			pkRes.StatusCode, actor, target)
		return syncTargetResult{Status: "fail", Error: "gh public-key upstream"}
	}
	var pk ghPublicKey
	if err := json.NewDecoder(pkRes.Body).Decode(&pk); err != nil {
		pkRes.Body.Close()
		log.Printf("SYNC_GH public-key decode actor=%q target=%q err=%v",
			actor, target, err)
		return syncTargetResult{Status: "fail", Error: "gh public-key decode"}
	}
	pkRes.Body.Close()

	encryptedB64, err := sealedBoxEncrypt([]byte(value), pk.Key)
	if err != nil {
		log.Printf("SYNC_GH sealed box encrypt actor=%q target=%q err=%v",
			actor, target, err)
		return syncTargetResult{Status: "fail", Error: "gh sealed-box encrypt"}
	}

	putBody, _ := json.Marshal(struct {
		EncryptedValue string `json:"encrypted_value"`
		KeyID          string `json:"key_id"`
		Visibility     string `json:"visibility"`
	}{EncryptedValue: encryptedB64, KeyID: pk.KeyID, Visibility: visibility})

	putURL := fmt.Sprintf("%s/orgs/%s/actions/secrets/%s", githubAPI, cfg.org, name)
	putReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, putURL,
		strings.NewReader(string(putBody)))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Accept", "application/vnd.github+json")
	putReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	putReq.Header.Set("User-Agent", "secrets-inventory-gcp")
	putRes, err := http_.Do(putReq)
	if err != nil {
		log.Printf("SYNC_GH put network actor=%q target=%q err=%v", actor, target, err)
		return syncTargetResult{Status: "fail", Error: "gh put network"}
	}
	defer putRes.Body.Close()
	if putRes.StatusCode != http.StatusCreated && putRes.StatusCode != http.StatusNoContent {
		log.Printf("SYNC_GH put upstream %d actor=%q target=%q",
			putRes.StatusCode, actor, target)
		return syncTargetResult{Status: "fail", Error: "gh put upstream"}
	}

	log.Printf("SYNC_GH ok actor=%q target=%q created=%v", actor, target, failIfExists)
	return syncTargetResult{
		Status:     "ok",
		SecretName: name,
		Created:    failIfExists, // fail_if_exists=true で 404 → created の意。handleGhPut と同 contract
	}
}

// propagateToCf は CF Secrets Store に値を投入する。既存 secret なら PATCH
// (rotate)、無ければ POST (create)。worker 側 rotate_secret の 3-target 並列
// 投入と同 semantics。
func propagateToCf(
	ctx context.Context,
	name, value string,
	scopes []string,
	failIfExists bool,
	cfg cfConfig,
	getter secretValueGetter,
	http_ httpDoer,
	actor string,
) syncTargetResult {
	target := sanitizeLogValue(name)
	token, err := getter.Get(ctx, cfg.tokenSecret)
	if err != nil {
		log.Printf("SYNC_CF token fetch failed actor=%q target=%q err=%v", actor, target, err)
		return syncTargetResult{Status: "fail", Error: "cf token fetch"}
	}

	// 既存 lookup — `?name=` filter で 1 件絞り込み
	existing, lookupErr := cfLookupByName(ctx, name, cfg, token, http_)
	if lookupErr != nil {
		log.Printf("SYNC_CF lookup network actor=%q target=%q err=%v", actor, target, lookupErr)
		return syncTargetResult{Status: "fail", Error: "cf lookup"}
	}
	if existing != "" && failIfExists {
		log.Printf("SYNC_CF conflict actor=%q target=%q already exists", actor, target)
		return syncTargetResult{Status: "fail", Error: "cf secret already exists"}
	}

	if existing != "" {
		// PATCH (rotate)
		patchBody, _ := json.Marshal(struct {
			Value string `json:"value"`
		}{Value: value})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
			cfg.base()+"/"+existing, strings.NewReader(string(patchBody)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "secrets-inventory-gcp")
		res, err := http_.Do(req)
		if err != nil {
			log.Printf("SYNC_CF patch network actor=%q target=%q err=%v",
				actor, target, err)
			return syncTargetResult{Status: "fail", Error: "cf patch network"}
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			log.Printf("SYNC_CF patch upstream %d actor=%q target=%q",
				res.StatusCode, actor, target)
			return syncTargetResult{Status: "fail", Error: "cf patch upstream"}
		}
		log.Printf("SYNC_CF rotated actor=%q target=%q id=%q",
			actor, target, sanitizeLogValue(existing))
		return syncTargetResult{
			Status:     "ok",
			SecretName: name,
			SecretID:   existing,
			Created:    false,
		}
	}

	// POST (create) - CF API は array of objects を期待する
	postBody, _ := json.Marshal([]struct {
		Name   string   `json:"name"`
		Value  string   `json:"value"`
		Scopes []string `json:"scopes"`
	}{{Name: name, Value: value, Scopes: scopes}})

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.base(), strings.NewReader(string(postBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secrets-inventory-gcp")
	res, err := http_.Do(req)
	if err != nil {
		log.Printf("SYNC_CF create network actor=%q target=%q err=%v",
			actor, target, err)
		return syncTargetResult{Status: "fail", Error: "cf create network"}
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		log.Printf("SYNC_CF create upstream %d actor=%q target=%q",
			res.StatusCode, actor, target)
		return syncTargetResult{Status: "fail", Error: "cf create upstream"}
	}

	raw, _ := io.ReadAll(res.Body)
	// CF API は単体 / 配列両方を返すことがある (handleCfCreate と同 envelope tolerance)
	var single cfEnvelope[cfRawSecret]
	if err := json.Unmarshal(raw, &single); err == nil && single.Success && single.Result.ID != "" {
		log.Printf("SYNC_CF created actor=%q target=%q id=%q",
			actor, target, sanitizeLogValue(single.Result.ID))
		return syncTargetResult{
			Status:     "ok",
			SecretName: name,
			SecretID:   single.Result.ID,
			Created:    true,
		}
	}
	var arr cfEnvelope[[]cfRawSecret]
	if err := json.Unmarshal(raw, &arr); err == nil && arr.Success &&
		len(arr.Result) > 0 && arr.Result[0].ID != "" {
		log.Printf("SYNC_CF created actor=%q target=%q id=%q",
			actor, target, sanitizeLogValue(arr.Result[0].ID))
		return syncTargetResult{
			Status:     "ok",
			SecretName: name,
			SecretID:   arr.Result[0].ID,
			Created:    true,
		}
	}
	log.Printf("SYNC_CF bad envelope actor=%q target=%q", actor, target)
	return syncTargetResult{Status: "fail", Error: "cf create bad envelope"}
}

// cfLookupByName は CF Secrets Store の `GET /secrets?name=NAME` で 1 件
// 絞り込み、見つかった secret の id を返す。0 件なら ""。
func cfLookupByName(
	ctx context.Context,
	name string,
	cfg cfConfig,
	token string,
	http_ httpDoer,
) (string, error) {
	listURL := cfg.base() + "?name=" + url.QueryEscape(name)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secrets-inventory-gcp")
	res, err := http_.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("cf list upstream %d", res.StatusCode)
	}
	var env cfEnvelope[[]cfRawSecret]
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return "", err
	}
	if !env.Success {
		return "", fmt.Errorf("cf list envelope success=false")
	}
	for _, s := range env.Result {
		if s.Name == name && s.ID != "" {
			return s.ID, nil
		}
	}
	return "", nil
}

// parseCsvQuery は ?scopes=a,b,c を ["a","b","c"] にする。空 string なら nil。
func parseCsvQuery(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
