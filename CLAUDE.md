# CLAUDE.md

Claude Code 向けの本リポジトリ作業ルール。

## Worktree / branch 命名規則

形式: `<issue-number>-<type>-<short-description>`

- `issue-number`: 必須。先に issue を立ててから worktree / branch を作る
- `type`: `feat` | `fix` | `refactor` | `infra`
- `short-description`: 半角小文字英数字とハイフン

例:

- `1-feat-cloud-run-bootstrap`
- `2-fix-pagination`

issue 番号を持たない branch (Claude Code が自動採番する `claude/...` 等)
で実装に入る前に、対応する issue を作成し、上記の形式で rename / 再切り出し
すること。

## PR description / commit message のキーワード

- 使用禁止: `Closes #N` / `Fixes #N` / `Resolves #N`
  - PR auto-merge が走った瞬間に issue が自動 close されるため、release 時の
    close 確認 UI と整合しない
- 使用推奨: `Refs #N` / `Related to #N` / `Part of #N`
  - GitHub の Development セクションには紐付くが auto-close されない
  - release tag 後に ci-dashboard 経由で目視 close する

PR テンプレートは `.github/pull_request_template.md` で `Refs` を強制する。

## このリポジトリの方針

- 本 repo は親 repo (`ippoan/secrets-inventory`) Worker から呼ばれる
  **Cloud Run proxy**。値を返す API は実装しない、**メタデータのみ read**
- **GCP の JSON key を一切発行しない**。Cloud Run の attached SA (`secrets-
  inventory-runtime*`) + ADC (metadata server) で runtime credential を取り、
  GitHub Actions → GCP の deploy credential も **WIF (GitHub OIDC trust)**
  で mint する。レポジトリシークレットに GCP key を置かない。
- runtime SA に付与する IAM role は **read-only を基本に**:
  - `roles/secretmanager.viewer` (Secret Manager メタデータ)
  - `roles/iam.securityReviewer` (SA 一覧 + project IAM policy + 各 SA の key 一覧)
  - `roles/policyanalyzer.activityAnalysisViewer` (Policy Analyzer の SA 最終認証時刻 read-only)
  - **(例外) `iam.serviceAccounts.disable` + `.enable` のみ custom role で許可**
    — pause / 即時復元用途、reversible なので付与する (下記 write 例外を参照)。
    `accessor` (= 値の取得) や delete / create は付けない
  - **(例外) `roles/secretmanager.secretVersionAdder`**
    — `/add-version` endpoint 用 (= rotate-mcp 経由の secret rotation)。
    既存 secret に新 version を投入する権限のみで、`secretmanager.admin` や
    `secretmanager.secretAccessor` (= 値の取得) は引き続き付けない。
    付与範囲は project 全体 / per-secret どちらでも可。Phase B 時点では
    project 全体 grant を許容するが、rotate 対象 secret が固定化された時点で
    per-secret IAM に絞ることを検討する
  - **(例外) custom role `secretsInventoryTempAccessor`** (`secretmanager.
    secrets.getIamPolicy` + `.setIamPolicy` permission のみ)
    — `/sync-from-gcp/:name` endpoint の source secret 読み出し用 (Refs #35)。
    proxy が**自分自身に対して** TTL ≤ 10 分の **Condition 付き** `secretAccessor`
    binding を `iam_temp_grant.go` 経由で grant → read → defer revoke する。
    cleanup 失敗時も CEL Condition (`request.time < timestamp(...)`) で
    auto-expire するため dead binding は時間で消える。
    この role は **自分の SA への accessor binding 追加** のみが想定された用途で、
    他 SA への grant や他 role の binding 追加は code path 上できない (TTL hard
    cap + Role / Title / Member の hard-code、`iam_temp_grant.go` 参照)。
    `setIamPolicy` という強い動詞権限を持つので CR で要重点 review。
  - **(例外) custom role `secretsInventoryCreator`** (`secretmanager.secrets.
    create` permission のみ)
    — `/create-secret` endpoint 用 (= rotate-mcp 経由の new secret 自動
    provisioning、ippoan/secrets-inventory#18 create_secret tool)。
    **GCP の Secret Manager には `secretCreator` という predefined role は
    存在しない** (`admin` / `secretAccessor` / `secretVersionAdder` /
    `secretVersionManager` / `viewer` の 5 つのみ)。`admin` は delete /
    setIamPolicy も含む過大権限なので避け、create だけを持つ単一権限の
    custom role を切る。secretVersionAdder と組み合わせて「create + 初版
    AddVersion」を 1 endpoint で完結させる (Refs #28)
  - **(例外) `roles/secretmanager.secretAccessor` を以下 2 secret 限定で**
    — `/cf/*` `/gh/*` endpoint (= ippoan/secrets-inventory#45 で worker
    から集約された CF / GitHub 経路) が CF API token と GitHub PAT を runtime
    取得するため。**project 全体には付与しない**、`cf-secrets-inventory-
    secrets-store-write` と `gh-secrets-inventory-org-secrets-write` の per-
    secret IAM で `secretAccessor` を grant する。proxy 側は 5 分 TTL cache
    して Secret Manager call を減らし、rotate 後の伝播 lag は最大 5 分
- 親 repo Worker からの呼び出しは `X-Inventory-API-Key` header 経由の
  shared secret 認証 (constant-time 比較)
- **write 系のうち以下のみ例外的に許可**。delete / create / role 変更 /
  SA key 管理は引き続き禁止:
  - SA `disable` / `enable` (`POST /sa-disable` / `/sa-enable`) — reversible、
    テスト・即時復元用途。`X-Actor-Email` header で actor audit trail
  - **secret `add-version` (`POST /add-version`)** — 既存 secret に新 version
    を投入。`secretmanager.secretVersionAdder` のみで動作 (= delete /
    create / value read 不可)。Body の `value` は **log / response に
    一切 echo しない** (handler / test で固定)。`X-Expected-Version-Id`
    header で TOCTOU 検証可能 (= "rotate 直前の version が想定通りでなければ
    409 で reject"、UI ヒューマンエラー対策。strict consistency が必要な
    場合は別途 KV lock を被せる)
  - **secret `create-secret` (`POST /create-secret`)** — 新規 secret を
    automatic replication で作成し、続けて initial value を version 1 として
    投入。`secretmanager.secretCreator` + `secretVersionAdder` の組み合わせで
    動作 (= delete / value read 不可)。Body の `value` は同じく log /
    response に echo しない。`X-Fail-If-Exists: true` (default) で既存 name
    衝突は 409、`false` 明示で既存 secret 再利用 (= new version 投入)。
    response の `created` boolean で 2 経路を識別できる。replication policy
    は automatic 固定 (region 限定が必要になれば別 endpoint or query で拡張)
  - **CF Secrets Store proxy (`/cf/secrets*`)** — ippoan/secrets-inventory#45
    で worker の `CF_API_TOKEN` binding を本 proxy に集約したもの。
    `GET /cf/secrets` (list)、`POST /cf/secrets` (create)、
    `POST /cf/secrets/{id}` (rotate = PATCH 委譲)。値は body `value` field
    のみ、log / response に echo しない。token は Secret Manager の
    `cf-secrets-inventory-secrets-store-write` から runtime 取得
    (5 分 TTL cache)。CF API は本 proxy 側で talking、worker は持たない
  - **GitHub org secrets proxy (`/gh/secrets*`)** — 同 #45。
    `GET /gh/secrets` (list)、`PUT /gh/secrets/{name}` (create/update)。
    GitHub Actions org secret 必須の **libsodium sealed box encrypt
    (Curve25519 + XSalsa20-Poly1305 + blake2b nonce) は proxy 側で実行**
    し、worker は素の value を送る (= worker から libsodium 依存を排除)。
    Go の `golang.org/x/crypto/nacl/box.SealAnonymous` を使用。PAT は
    `gh-secrets-inventory-org-secrets-write` から runtime 取得 (5 分 TTL)。
    `X-Fail-If-Exists: true` で事前 GET → 200 なら 409 reject

## 環境

親 repo に揃えて **staging を実運用環境**とする。

| env | Cloud Run service | trigger |
|---|---|---|
| staging (live) | `secrets-inventory-gcp-staging` | `main` push / PR (non-draft) |
| production | `secrets-inventory-gcp` | `v*` tag push |

PR を上げると staging に auto-deploy される。production は当面未使用、
`v*` タグでだけ deploy。

## デプロイ

ippoan の Cloud Run deploy 標準パターンに揃える: caller workflow で
**Docker build + GHCR push** → `ippoan/ci-workflows/.github/workflows/
cloud-run-deploy.yml` reusable で **AR remote-repo (pull-through cache)
経由で digest-pinned deploy**。

> **GCP key 0 個運用** は runtime / deploy 両側で達成:
>
> - **Runtime** (Cloud Run → Secret Manager): Cloud Run の attached SA +
>   ADC (metadata server)
> - **Deploy** (GitHub Actions → GCP): WIF (Workload Identity Federation +
>   GitHub OIDC trust)。issue ippoan/secrets-inventory#3 で明記された方針。

### GCP 側 (one-time、`cloudsql-sv` project)

既存 リソースをできるだけ流用するが、Deployer SA は WIF 専用として新規
作成する。

- **WIF Pool + Provider** (既存、`gh-actions-pool` / `github`):
  ```bash
  PROJECT=cloudsql-sv
  POOL=gh-actions-pool
  PROVIDER=github

  # (既に存在する場合は describe で確認するだけ)
  gcloud iam workload-identity-pools describe "$POOL" \
    --project="$PROJECT" --location=global

  gcloud iam workload-identity-pools providers describe "$PROVIDER" \
    --project="$PROJECT" --location=global --workload-identity-pool="$POOL"
  ```
  full path: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gh-actions-pool/providers/github`

  attribute_condition は `assertion.repository_owner == 'ippoan'` で
  ippoan org 配下の全 repo を受け入れる (個別 repo の impersonation 制御は
  SA-level の workloadIdentityUser binding で行う設計)。

- **Deployer SA** (`staging-deploy@cloudsql-sv.iam.gserviceaccount.com`):
  - display name: `Staging Deploy (GitHub Actions)`
  - role: `roles/run.admin`, `roles/iam.serviceAccountUser` (Cloud Run に
    runtime SA を attach するため), `roles/artifactregistry.reader`,
    `roles/secretmanager.viewer` (secret-verify 用),
    `projects/cloudsql-sv/roles/secretsInventoryLabeler` (apply_labels 用
    custom role、`secretmanager.secrets.update` + `.get`),
    `roles/secretmanager.secretAccessor` (Cloud Run deploy 時 secret 注入用),
    `roles/logging.logWriter`, `roles/logging.viewer`, `roles/cloudfunctions.viewer`
  - **JSON key は発行しない** (system-managed key のみ、user-managed key の
    自動 rotation は GCP 側に任せる)
  - WIF principal binding (`secrets-inventory-gcp` と `secrets-inventory`
    の 2 repo から impersonate 可、新 repo を追加するときは binding を 1 行
    増やす):
    ```bash
    PROJECT_NUMBER=$(gcloud projects describe cloudsql-sv --format='value(projectNumber)')

    for REPO in ippoan/secrets-inventory-gcp ippoan/secrets-inventory; do
      gcloud iam service-accounts add-iam-policy-binding \
        staging-deploy@cloudsql-sv.iam.gserviceaccount.com \
        --project=cloudsql-sv \
        --role="roles/iam.workloadIdentityUser" \
        --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/gh-actions-pool/attribute.repository/$REPO"
    done
    ```
  - prod 用 (`cloud-run-deployer@cloudsql-sv.iam.gserviceaccount.com` 等)
    は production deploy を始めるタイミングで別 SA + WIF binding を作る。
    `v*` tag push でだけ使う想定。

- **Runtime SA (Cloud Run attached)**:
  `secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com` (既存、
  `roles/secretmanager.viewer` を持つことを確認。**JSON key は発行しない**
  = ADC 経由で取る)

  rotate-mcp (= `POST /add-version`) + create-mcp (= `POST /create-secret`)
  を有効化する場合は追加で:
  ```bash
  SA="secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com"

  # /add-version 用 (= secrets-inventory MCP の rotate_secret tool)
  gcloud projects add-iam-policy-binding cloudsql-sv \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretVersionAdder"

  # /create-secret 用 (= secrets-inventory MCP の create_secret tool)
  # GCP には secretCreator predefined role が存在しないので、create だけを
  # 持つ custom role を 1 個切ってそれを bind する (admin は delete /
  # setIamPolicy も含むので避ける)。
  gcloud iam roles create secretsInventoryCreator \
    --project=cloudsql-sv \
    --title="Secrets Inventory Creator" \
    --description="Create new Secret Manager secrets only (no delete, no value read)" \
    --permissions=secretmanager.secrets.create \
    --stage=GA

  gcloud projects add-iam-policy-binding cloudsql-sv \
    --member="serviceAccount:$SA" \
    --role="projects/cloudsql-sv/roles/secretsInventoryCreator"

  # /sync-from-gcp/:name 用 (= secrets-inventory MCP の sync 経路) — Refs #35
  # 任意 source secret を CF / GitHub に伝播する endpoint で、source value を
  # 読むために proxy が **自分自身に** TTL ≤ 10 分の Condition 付き
  # secretAccessor binding を貼って read → 自動 revoke する。
  # secretmanager.secrets.{get,set}IamPolicy のみを持つ custom role を切る
  # (admin の他成分 = delete / direct value read は付与しない)。
  gcloud iam roles create secretsInventoryTempAccessor \
    --project=cloudsql-sv \
    --title="Secrets Inventory Temp Accessor" \
    --description="Manage IAM policy on Secret Manager secrets (used for short-lived self-grant from /sync-from-gcp; no delete, no direct value read)" \
    --permissions=secretmanager.secrets.getIamPolicy,secretmanager.secrets.setIamPolicy \
    --stage=GA

  gcloud projects add-iam-policy-binding cloudsql-sv \
    --member="serviceAccount:$SA" \
    --role="projects/cloudsql-sv/roles/secretsInventoryTempAccessor"
  ```
  (= 値の追加 / 新規 secret 作成 / sync 時の TTL 付き self-grant、いずれも
  delete / accessor の永続付与は含まない最小権限)

  > **`secretsInventoryTempAccessor` を grant した結果**: operator が
  > `/sync-from-gcp/:name` を呼ぶ前に source secret 単位の `secretAccessor`
  > を gcloud で手動 grant する step は **不要** になる。proxy が
  > `iam_temp_grant.go` 経由で grant → read → revoke を 1 リクエスト内で
  > 完結させる。grant 失敗時 (= role 未付与等) は fallback して従来通り
  > "operator pre-grant 必須" 動作にデグレード (log に明記)。

  > **必須 setup**: この 2 role の grant が漏れると `/add-version` /
  > `/create-secret` が **gRPC PermissionDenied → handler が 502 にラップ**
  > して返し、worker からは `gcp proxy 502: error code: 502` (= CF edge
  > synthetic body) として観測される。read endpoint は viewer role だけで
  > 動くため、write を実トラフィックに当てるまで露見しない (Refs #28)。

  `/cf/*` `/gh/*` endpoint (= #45 worker 集約) を有効化する場合は CF API
  token と GitHub PAT を Secret Manager に投入し、**per-secret IAM** で
  `secretAccessor` を runtime SA に付与する (project 全体に拡張しないこと):
  ```bash
  # Secret 作成 + initial value 投入は user が手動 (= 値投入は人間 boundary)
  echo -n "<CF API token (write)>" | gcloud secrets create \
    cf-secrets-inventory-secrets-store-write \
    --project=cloudsql-sv --replication-policy=automatic --data-file=-
  echo -n "<GitHub PAT (write, classic or fine-grained)>" | gcloud secrets create \
    gh-secrets-inventory-org-secrets-write \
    --project=cloudsql-sv --replication-policy=automatic --data-file=-

  # runtime SA に per-secret accessor grant
  for SECRET in cf-secrets-inventory-secrets-store-write gh-secrets-inventory-org-secrets-write; do
    gcloud secrets add-iam-policy-binding "$SECRET" \
      --project=cloudsql-sv \
      --member="serviceAccount:secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com" \
      --role="roles/secretmanager.secretAccessor"
  done
  ```
  CF token に必要な scope: `Account.Secrets Store:Edit` (read + write)。
  GitHub PAT に必要な scope: `admin:org` (= org secrets write)。fine-grained
  PAT なら `organization_secrets: read+write`。値は Secret Manager に置く
  だけで、worker (`secrets-inventory`) からは見えない

- **AR remote-repo**: `asia-northeast1-docker.pkg.dev/cloudsql-sv/ghcr/`
  (既存、daiun-salary 等と共有。`ippoan/secrets-inventory-gcp` という
  path で同 remote-repo に乗る)

- **Shared API key**: Google Secret Manager に
  `SECRETS_INVENTORY_GCP_PROXY_API_KEY_STAGING` (staging) /
  `SECRETS_INVENTORY_GCP_PROXY_API_KEY` (prod) を新規作成
  + `secrets-inventory-viewer` SA に `roles/secretmanager.secretAccessor`
  を **この secret 限定で** 付与
  + 同値を親 repo (`ippoan/secrets-inventory`) の Cloudflare Secrets Store
  にも投入

### Cloud Run service の初回作成 (user 手動)

`cloud-run-deploy.yml` reusable は `gcloud run services update --image`
を叩く設計で、**service が既存前提**。1 回だけ user が手動で作成:

```bash
PROJECT_STAGING="cloudsql-sv"
REGION="asia-northeast1"
RUNTIME_SA="secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com"

gcloud run deploy secrets-inventory-gcp-staging \
  --project="$PROJECT_STAGING" \
  --region="$REGION" \
  --image="asia-northeast1-docker.pkg.dev/$PROJECT_STAGING/ghcr/ippoan/secrets-inventory-gcp:latest" \
  --service-account="$RUNTIME_SA" \
  --allow-unauthenticated \
  --ingress=all \
  --set-env-vars="GCP_PROJECT_ID=$PROJECT_STAGING,CF_ACCOUNT_ID=24b45709d060d957340180e995f0d373,CF_STORE_ID=bd7bc91a3e5f4111add4acf6cb4b8733,CF_TOKEN_SECRET_NAME=cf-secrets-inventory-secrets-store-write,GITHUB_ORG=ippoan,GH_TOKEN_SECRET_NAME=gh-secrets-inventory-org-secrets-write" \
  --update-secrets="INVENTORY_API_KEY=SECRETS_INVENTORY_GCP_PROXY_API_KEY_STAGING:latest"
```

`CF_ACCOUNT_ID` / `CF_STORE_ID` / `GITHUB_ORG` は plain env var (= 親 repo
の wrangler.jsonc と同値の constant)。`CF_TOKEN_SECRET_NAME` /
`GH_TOKEN_SECRET_NAME` は Secret Manager 上の **secret short name** を
plain env で渡し、proxy が runtime に AccessSecretVersion で値を取る (= 値
そのものを Cloud Run env に焼かない設計)。

**運用 setup と code deploy の分離**: 上記 5 つの env は proxy boot 時には
optional 扱い (= 1 つでも空なら `/cf/*` `/gh/*` だけが 503 "endpoint not
configured" を返す)。これにより:

1. ci.yml の `set_env_vars` 更新前でも proxy の deploy が成功する (= boot
   時に `mustEnv` が落とさない)
2. Secret Manager への token 投入 + per-secret IAM grant + Cloud Run service
   への env 注入は **user が運用 step として後追い**できる
3. 既存 `/list-secrets` `/list-service-accounts` 等の read endpoint は env
   未設定でも従来どおり動作する

deploy 後、5 つの env を `gcloud run services update --set-env-vars ...` で
注入した瞬間に `/cf/*` `/gh/*` が active 化する。

これ以降は workflow が image を update する。

### GitHub repo 側 (Settings → Secrets and variables → Actions)

**Secrets (encrypted, repo-level):**

なし。WIF に切り替えたことにより、以前設定していた `GCP_SA_KEY` secret は
**不要 → 削除**してよい。

**Variables (plain text, repo-level):**

- `GCP_REGION` = `asia-northeast1`
- `GCP_PROJECT_ID_STAGING` = `cloudsql-sv`
- `GCP_WIF_PROVIDER` =
  `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/gh-actions-pool/providers/github`
- `GCP_WIF_SERVICE_ACCOUNT_STAGING` =
  `staging-deploy@cloudsql-sv.iam.gserviceaccount.com`
  (org-level vars として登録済 = `ippoan` org 配下の全 public repo で共有)
- (production を動かす段階で `GCP_PROJECT_ID` と
  `GCP_WIF_SERVICE_ACCOUNT` も追加)

`vars.GCP_PROJECT_ID_STAGING` / `GCP_WIF_PROVIDER` /
`GCP_WIF_SERVICE_ACCOUNT_STAGING` のいずれかが空だと workflow の
`deploy-staging` job が `if:` で skip される (PR の必須 check
`ci / vet` / `ci / test` / `ci / build` だけで通る)。setup 完了後に
variable を入れた瞬間 deploy が動き始める。

org-level に寄せるか repo-level に置くかは値の性質次第:

- `GCP_REGION` / `GCP_WIF_PROVIDER` (org 横断 pool/provider) → org 推奨
- `GCP_PROJECT_ID_STAGING` も service 全部が `cloudsql-sv` なら org 可
- `GCP_WIF_SERVICE_ACCOUNT_*` は service ごとに違うので repo-level

## ローカル開発

```bash
go vet ./...
go test ./...
go build .

# ローカル run (実 GCP を叩く場合は ADC が必要)
gcloud auth application-default login
GCP_PROJECT_ID=your-project INVENTORY_API_KEY=dev-key ./secrets-inventory-gcp
```
