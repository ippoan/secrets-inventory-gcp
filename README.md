# secrets-inventory-gcp

[`ippoan/secrets-inventory`](https://github.com/ippoan/secrets-inventory) (Cloudflare Worker) から GCP Secret Manager の metadata を読むための **Cloud Run proxy** (Go service)。

GCP Service Account の JSON key (~2KB) は Cloudflare Secrets Store の 1024 byte 上限に収まらないため、CF Worker から直接 GCP API を叩く構成は採用しなかった。代わりに Cloud Run 上で attached service account + ADC (metadata server) で credential を取り、Worker からは shared secret 経由でこの proxy を叩く。

**システム全体で GCP の JSON key を 0 個発行しない**運用が目標。

## アーキテクチャ

```
[CF Worker (ippoan/secrets-inventory)]
       │  HTTPS + X-Inventory-API-Key header
       ▼
[Cloud Run service (この repo)]
       │  Application Default Credentials (metadata server)
       ▼
[GCP Secret Manager API]
```

| 認証境界 | 方式 | 鍵 |
|---|---|---|
| User → CF Worker | CF Access (Google OAuth) | 0 |
| CF Worker → Cloud Run | `X-Inventory-API-Key` header (32 byte shared secret) | Cloudflare Secrets Store + Google Secret Manager に同値を投入 |
| Cloud Run → GCP API | ADC (metadata server) | **0 (JSON key 発行しない)** |

検討経緯と却下した選択肢は親 repo の [issue #3](https://github.com/ippoan/secrets-inventory/issues/3) を参照。

## 別 repo にした理由

- 本 repo は **Go service**、親 repo は TypeScript Worker。CI / build / dependency が完全に独立
- Cloud Run の deploy 単位と GitHub repo を 1:1 にすると、deployer SA の権限境界 / rotation 計画 / Actions ログが repo と完全一致するので運用が分かりやすい (rust-alc-api 等の既存 ippoan deploy パターンと同じ思想)
- subdirectory pattern (`cloud-run/`) も検討したが、別 repo の方が運用境界が明確

## 環境構成

親 repo と揃えて **staging を実運用環境**とする。`v*` タグを切ったときだけ production にも反映する想定 (当面は staging だけ動かす)。

| env | Cloud Run service | trigger |
|---|---|---|
| staging (live) | `secrets-inventory-gcp-staging` | `main` push / PR (non-draft) |
| production | `secrets-inventory-gcp` | `v*` tag push |

## エンドポイント

| method | path | 認証 | 説明 |
|---|---|---|---|
| GET | `/health` | 不要 | health check (Cloud Run liveness) |
| GET | `/list-secrets` | `X-Inventory-API-Key` 必須 | `projects/{GCP_PROJECT_ID}/secrets` を全件 list して JSON で返す |

> Note: 以前は `/healthz` だったが、Cloud Run / GFE が `/healthz` を reserved path として扱うらしく Google edge で 404 を返してしまうため `/health` に rename した。

`/list-secrets` のレスポンスは Worker 側の `SecretMetadata[]` 形にそのまま map できる shape (`name` は `projects/.../secrets/` prefix を剥がした短縮名)。

read endpoint の他に write/proxy endpoint (`/add-version` / `/create-secret` /
`/cf/secrets*` / `/gh/secrets*` / `/sync-from-gcp/:name` 等) を持つ。全 endpoint と
最小権限の方針は [`CLAUDE.md`](CLAUDE.md) を参照。

### GitHub org secret 書込の認証 (App mode / 別 org 対応)

`/gh/secrets*` と `/sync-from-gcp` の `?gh_org=` は **default org 以外**にも書ける。
認証 backend は 2 mode (Refs #51 / #49):

- **GitHub App installation token mode (推奨)** — env `GH_APP_ID_SECRET_NAME` +
  `GH_APP_PRIVATE_KEY_SECRET_NAME` (Secret Manager の secret 名)。App JWT →
  installation token (1h、org 別 cache) で、**App が install された org すべて**に
  書ける = per-org PAT 不要。App 側に Organization permissions → Secrets: Read and
  write が必要。鍵 PEM は PKCS#1 / PKCS#8 両対応。
- **PAT mode (fallback)** — `GH_TOKEN_SECRET_NAME` (default org) + `GH_EXTRA_ORGS`
  (comma 区切り `org=tokenSecretName` allowlist、org ごとに専用 PAT)。App mode 無効時。

> **PAT mode は 2026-06 に退役 (retired)。** fallback 用の fine-grained PAT
> `gh-secrets-inventory-org-secrets-write` は有効期限が来たため、**rotate せず
> 失効させ無効化した**。現在 Cloud Run service (`secrets-inventory-gcp-staging`)
> には `GH_APP_ID_SECRET_NAME=CI_APP_ID` / `GH_APP_PRIVATE_KEY_SECRET_NAME=CI_APP_PRIVATE_KEY`
> が設定済みで **App mode が primary**。App mode 有効時は PAT は実行時に読まれない
> ため、`gh-secrets-inventory-org-secrets-write` が失効しても `/gh/*` `/sync-from-gcp`
> は影響を受けない (= GitHub 通知の期限切れアラートは無視してよい)。
> `GH_TOKEN_SECRET_NAME` env は dormant fallback として残置。PAT fallback を将来
> 復活させたい場合は新しい fine-grained PAT (`organization_secrets: read+write`、
> resource owner = `ippoan`) を発行して同名 secret を再作成 + version 投入する。

新 org オンボードは「App を install + permission 承認 → `sync_from_gcp { gh_org }` で
配布 → caller は named secret 明示渡し」の 3 step (`secrets: inherit` はクロス org で
効かない)。詳細は親 repo `ippoan/secrets-inventory` README / `ci-workflows` CLAUDE.md。

## GCP 側 setup (one-time)

実行コマンド込みの正本は
[`.claude/skills/secrets-inventory-gcp-map/SKILL.md`](.claude/skills/secrets-inventory-gcp-map/SKILL.md)
の「GCP 側 (one-time、`cloudsql-sv` project)」節
(経緯は [issue #1](https://github.com/ippoan/secrets-inventory-gcp/issues/1)、
WIF 方針は [ippoan/secrets-inventory#3](https://github.com/ippoan/secrets-inventory/issues/3))。要点:

- **GCP の user-managed JSON key は 0 本** — runtime も deploy も発行しない
- **deploy** = WIF (Workload Identity Federation + GitHub OIDC trust)。
  pool / provider は既存の `gh-actions-pool` / `github`、impersonate 先は
  `staging-deploy@cloudsql-sv.iam.gserviceaccount.com`
  (`roles/run.admin` / `iam.serviceAccountUser` / `artifactregistry.reader` /
  `secretmanager.viewer` / `secretmanager.secretAccessor` / custom role
  `secretsInventoryLabeler` ほか)。repo ごとの impersonate 許可は SA-level の
  `roles/iam.workloadIdentityUser` principal binding で行う
- **runtime** = Cloud Run attached SA
  `secrets-inventory-viewer@cloudsql-sv.iam.gserviceaccount.com` + ADC
  (metadata server)。IAM は read-only を基本
  (`roles/secretmanager.viewer` / `roles/iam.securityReviewer` /
  `roles/policyanalyzer.activityAnalysisViewer`) に、reversible な write 例外のみ追加
- shared secret (32 byte) を Google Secret Manager に格納し、Cloud Run が
  起動時に env var `INVENTORY_API_KEY` として参照
- 同値を Cloudflare Secrets Store にも投入 (`SECRETS_INVENTORY_GCP_PROXY_API_KEY`)

> **GitHub repo secret に GCP key は置かない。** WIF 以前に使っていた
> `GCP_SA_KEY` secret は不要になり削除済み。代わりに repo / org variables
> `GCP_REGION` / `GCP_PROJECT_ID_STAGING` / `GCP_WIF_PROVIDER` /
> `GCP_WIF_SERVICE_ACCOUNT_STAGING` を設定する
> (いずれかが空だと `ci.yml` の `deploy-staging` job は `if:` で skip される)。
>
> 旧設計にあった `cloud-run-deployer-staging` / `cloud-run-deployer`
> (JSON key を repo secret `GCP_DEPLOY_SA_KEY*` に登録する deploy SA) と
> `secrets-inventory-runtime-staging` / `secrets-inventory-runtime` (runtime SA) は
> **採用されなかった初期案**で、現行構成では使っていない。

## 開発ルール

- branch / worktree 命名と `Refs #N` 規約: [`CLAUDE.md`](CLAUDE.md) (TBD)
- PR テンプレート: [`.github/pull_request_template.md`](.github/pull_request_template.md) (TBD)
- 値は一切扱わない。**メタデータのみ read**
- write 系 (create / update / delete) は実装しない
