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
- runtime SA に付与する IAM role は **read-only に限定**:
  - `roles/secretmanager.viewer` (Secret Manager メタデータ)
  - `roles/iam.securityReviewer` (SA 一覧 + project IAM policy + 各 SA の key 一覧)
  - `roles/policyanalyzer.activityAnalysisViewer` (Policy Analyzer の SA 最終認証時刻 read-only)
  `accessor` (= 値の取得) は付けない。書き込み系の role も付けない
- 親 repo Worker からの呼び出しは `X-Inventory-API-Key` header 経由の
  shared secret 認証 (constant-time 比較)
- write 系 (create / update / delete) のエンドポイントは追加しない

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

- **WIF Pool + Provider** (新規):
  ```bash
  PROJECT=cloudsql-sv
  POOL=github
  PROVIDER=ippoan

  gcloud iam workload-identity-pools create "$POOL" \
    --project="$PROJECT" --location=global \
    --display-name="GitHub Actions"

  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
    --project="$PROJECT" --location=global \
    --workload-identity-pool="$POOL" \
    --display-name="ippoan org OIDC" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
    --attribute-condition="assertion.repository_owner=='ippoan'"
  ```
  full path: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/ippoan`

- **Deployer SA** (`cloud-run-deployer-staging@cloudsql-sv.iam.gserviceaccount.com`):
  - role: `roles/run.admin`, `roles/iam.serviceAccountUser` (Cloud Run に
    runtime SA を attach するため), `roles/artifactregistry.reader`
  - **JSON key は発行しない**
  - WIF principal binding (`secrets-inventory-gcp` repo だけから impersonate 可):
    ```bash
    PROJECT_NUMBER=$(gcloud projects describe cloudsql-sv --format='value(projectNumber)')
    PRINCIPAL="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/ippoan/secrets-inventory-gcp"

    gcloud iam service-accounts add-iam-policy-binding \
      cloud-run-deployer-staging@cloudsql-sv.iam.gserviceaccount.com \
      --project=cloudsql-sv \
      --role="roles/iam.workloadIdentityUser" \
      --member="$PRINCIPAL"
    ```
  - prod 用 (`cloud-run-deployer@cloudsql-sv.iam.gserviceaccount.com`) も
    同様に作成 + WIF binding。`v*` tag push でだけ使うので連動するのは
    production deploy を始めるタイミングでよい。

- **Runtime SA (Cloud Run attached)**:
  `secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com` (既存、
  `roles/secretmanager.viewer` を持つことを確認。**JSON key は発行しない**
  = ADC 経由で取る)

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
  --set-env-vars="GCP_PROJECT_ID=$PROJECT_STAGING" \
  --update-secrets="INVENTORY_API_KEY=SECRETS_INVENTORY_GCP_PROXY_API_KEY_STAGING:latest"
```

これ以降は workflow が image を update する。

### GitHub repo 側 (Settings → Secrets and variables → Actions)

**Secrets (encrypted, repo-level):**

なし。WIF に切り替えたことにより、以前設定していた `GCP_SA_KEY` secret は
**不要 → 削除**してよい。

**Variables (plain text, repo-level):**

- `GCP_REGION` = `asia-northeast1`
- `GCP_PROJECT_ID_STAGING` = `cloudsql-sv`
- `GCP_WIF_PROVIDER` =
  `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github/providers/ippoan`
- `GCP_WIF_SERVICE_ACCOUNT_STAGING` =
  `cloud-run-deployer-staging@cloudsql-sv.iam.gserviceaccount.com`
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
