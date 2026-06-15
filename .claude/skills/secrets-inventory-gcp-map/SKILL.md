---
name: secrets-inventory-gcp-map
generated-from: secrets-inventory-gcp:a76a7960263627c3724c123850267f16e0ca7f96
paths: [cf.go, convert_pkcs8.go, gh.go, gh_variables.go, http_doer.go, iam_temp_grant.go, main.go, mint_health_oauth_jwt.go, secret_value.go, sync_from_gcp.go]
description: ippoan/secrets-inventory-gcp (Go / Cloud Run、ippoan/secrets-inventory Worker から GCP Secret Manager / IAM / CF Secrets Store / GitHub org secret を代行する薄い proxy) の構造ナビゲーション。read 系 (list-secrets / list-service-accounts) と最小 write 例外 (add-version / create-secret / sa-disable / cf・gh proxy / sync-from-gcp) の endpoint 配置・認証境界・GCP key 0 個運用・rotate guardrail を 1 枚にまとめる。トリガー:「secrets-inventory-gcp」「list-secrets」「add-version」「create-secret」「sync-from-gcp」「sa-disable」「cf service token」「gh org secret」「gh repo variable」「/gh/variables」「Actions variable」「X-Inventory-API-Key」「rotate-mcp」「secret rotate」等。
---

# secrets-inventory-gcp-map — ippoan/secrets-inventory-gcp 構造ナビゲーション

Go の Cloud Run service。`ippoan/secrets-inventory` (Cloudflare Worker) から呼ばれ、GCP
Secret Manager / IAM の **メタデータ read** を基本に、最小限の reversible write (rotate /
create / SA disable / CF・GitHub secret proxy) を ADC (metadata server) 経由で代行する。
`secrets-inventory` MCP の rotate / create / sync tool 群の GCP 側 executor。

> ここは索引 (pointer)。細部は repo 側が正。frontmatter の `generated-from` が現在の
> repo tree-sha とズレたら session-start hook が再生成を促す → その時 tree-sha を更新する。

## 区画 (フラットな単一 package、`main`)

| ファイル | 主要 symbol | 役割 |
|---|---|---|
| `main.go` | `main` / `newMuxWith` / `requireAPIKey` / `mustEnv` / `handleHealth` / `handleListSecrets` / `handleListServiceAccounts` / `handleSetSADisabled` / `handleAddSecretVersion` / `handleCreateSecret` | HTTP layer。route 登録 + API key 認証 + read/SA/secret write handler |
| `cf.go` | `cfConfig` / `handleCfList` / `handleCfCreate` / `handleCfRotate` / `handleCfServiceToken{List,Create,Rotate,Delete}` | CF Secrets Store + CF service token proxy。token は SM から runtime 取得 |
| `gh.go` | `ghConfig` / `handleGhList` / `handleGhPut` / `sealedBoxEncrypt` | GitHub org secrets proxy。**libsodium sealed box encrypt を proxy 側で実行** |
| `gh_variables.go` | `handleGhVariablesList` / `handleGhVariablePut` / `parseGhRepoParam` / `newGhRequest` | GitHub Actions **repo variables** proxy (平文 config、secret ではない = 暗号化なし)。`?repo=owner/name`、upsert は GET→POST/PATCH |
| `sync_from_gcp.go` | `handleSyncFromGcp` / `propagateToGh` / `propagateToCf` / `cfLookupByName` | source SM secret を CF / GitHub に伝播する `/sync-from-gcp/:name` |
| `iam_temp_grant.go` | `liveTempGrantManager` / `GrantThenRead` / `appendTempBinding` / `tempGrantExpression` | sync 用に proxy が**自分自身に** TTL≤10 分 Condition 付き accessor を grant→read→revoke |
| `secret_value.go` | `liveSecretValueGetter` / `cachedSecretValueGetter` | SM short name → value 取得 (5 分 TTL cache、cf/gh の token 用) |
| `convert_pkcs8.go` | `convertPkcs1ToPkcs8` / `handleConvertPkcs8` | `/convert-pkcs8/` PKCS1→PKCS8 変換 |
| `mint_health_oauth_jwt.go` | `handleMintHealthOAuthJwt` / `mintJwtClaims` / `signHS256Jwt` | `/mint-health-oauth-jwt` HS256 JWT 発行 |
| `http_doer.go` | `httpDoer` / `mustCompile` | HTTP client interface (test 差し替え用) |
| `*_test.go` | — | handler は fake lister/getter、live 側は `httptest.Server` で GCP/CF/GH mock |
| `Dockerfile` / `coverage_100.toml` | — | Cloud Run image / カバレッジ 100% gate |

## entrypoint / route (main.go の `newMuxWith`)

`/health` 以外は全て `X-Inventory-API-Key` (constant-time 比較) 必須。`/cf/*` `/gh/*` は
さらに `requireCfConfigured` / `requireGhConfigured` で gate (env 未設定なら 503)。

| method | path | handler | 種別 |
|---|---|---|---|
| GET | `/health` | `handleHealth` | 認証不要 (`/healthz` は GFE reserved で避ける) |
| GET | `/list-secrets` | `handleListSecrets` | **read** SM secret 一覧 (値は返さない) |
| GET | `/list-service-accounts` | `handleListServiceAccounts` | **read** SA + key + 最終認証時刻 |
| POST | `/sa-disable` `/sa-enable` | `handleSetSADisabled` | write 例外 (reversible)。`X-Actor-Email` で audit |
| POST | `/add-version` | `handleAddSecretVersion` | write 例外 (rotate-mcp)。`secretVersionAdder` のみ |
| POST | `/create-secret` | `handleCreateSecret` | write 例外 (create-mcp)。`secretCreator` + `secretVersionAdder` |
| POST | `/mint-health-oauth-jwt` | `handleMintHealthOAuthJwt` | HS256 JWT mint |
| GET | `/sync-from-gcp/:name` | `handleSyncFromGcp` | source secret を CF / GitHub に伝播 |
| POST | `/convert-pkcs8/` | `handleConvertPkcs8` | PKCS1→PKCS8 |
| GET/POST | `/cf/secrets` `/cf/secrets/{id}` | `handleCfList/Create/Rotate` | CF Secrets Store proxy |
| GET/POST/DELETE | `/cf/service-tokens` `/cf/service-tokens/{id}` | `handleCfServiceToken*` | CF service token (delete 時 `?sm_secret_name=` で audit label patch) |
| GET/PUT | `/gh/secrets` `/gh/secrets/{name}` | `handleGhList/Put` | GitHub org secret proxy (sealed box) |
| GET/PUT | `/gh/variables` `/gh/variables/{name}` | `handleGhVariablesList/Put` | GitHub Actions repo variables proxy (平文、`?repo=owner/name`) |

## gotcha (CLAUDE.md / README 由来)

- **GCP の JSON key を一切発行しない**: runtime = Cloud Run attached SA (`secrets-inventory-viewer`) + ADC、deploy = WIF + GitHub OIDC。
- **値は read しない / 返さない / echo しない**: 全 write の body `value` は log / response に一切出さない (handler / test で固定)。read 系は metadata のみ。
- **read-only + 最小 write 例外**の IAM 設計。`secretAccessor` (= 値取得) や delete / create は原則付けない。write 例外ごとに専用 custom role を切る:
  - `add-version` → `secretmanager.secretVersionAdder`
  - `create-secret` → custom role `secretsInventoryCreator` (= `secrets.create`。GCP に `secretCreator` predefined role は無い)
  - `sync-from-gcp` → custom role `secretsInventoryTempAccessor` (= `getIamPolicy` + `setIamPolicy`。`setIamPolicy` は強い動詞権限なので **CR 重点 review**)
  - `cf/*` `gh/*` token → 2 secret 限定の `secretAccessor` (project 全体には付けない)
  - CF service token delete の label patch → custom role `secretsInventoryLabeler` (= `secrets.update` + `.get`)
- **add-version の `value` 末尾空白は default で 400 reject** (`X-Allow-Trailing-Whitespace: true` で明示許可)。`echo` 投入で末尾 `\n` が混入し OAuth audience compare が silent fail した事故 (auth-worker#208) の再発防止。`X-Expected-Version-Id` で TOCTOU 検証可。
- **write IAM grant 漏れ → gRPC PermissionDenied → 502 ラップ**。read endpoint は viewer role だけで動くため、write を実トラフィックに当てるまで露見しない (Refs #28)。
- `cf/*` `gh/*` の 5 env は boot 時 optional 扱い (1 つでも空なら該当 endpoint だけ 503)。token 投入 / per-secret IAM grant / env 注入は運用 step として後追いできる。
- `Closes/Fixes/Resolves #N` 禁止 → `Refs #N` (release 時 ci-dashboard 経由で目視 close)。

## CCoW / CI から見た立ち位置

- 親 (`ippoan/secrets-inventory` Worker) → 本 proxy → GCP の **2 段モデル**。CF Secrets Store の 1024 byte 上限に SA JSON key (~2KB) が収まらない問題の回避策。
- staging (`secrets-inventory-gcp-staging`) を **実運用環境**として扱う。production (`v*` tag) は当面未使用。
- CI は `ci-workflows/go-ci.yml` (`vet`/`test`/`build` + opt-in `secret-verify`、`coverage_100.toml` で 100% gate)。auto-merge は caller `ci.yml` 側で `auto-merge.yml` を組む。deploy は `cloud-run-deploy.yml` reusable (AR remote-repo 経由 digest-pinned)。

## 関連 skill

- `release-wave-gcp-map` — 同じ「CF Worker → Cloud Run → GCP API」2 段モデルの姉妹 repo (参照モデル)
- `secret-inject` — OAT→binding_jwt→`/mcp/secret-upload` で no-leak secret 投入 (本 proxy の write 経路の上流)
- `repo-map` / `cross-repo-symbol-index` — この per-repo map の運用方針 (generated-from 鮮度 hook)
