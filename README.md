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

## GCP 側 setup (one-time)

詳細は [issue #1](https://github.com/ippoan/secrets-inventory-gcp/issues/1) を参照。要点:

- `cloud-run-deployer-staging` / `cloud-run-deployer` SA (deploy 用、JSON
  key を発行して GitHub repo secret `GCP_DEPLOY_SA_KEY_STAGING` /
  `GCP_DEPLOY_SA_KEY` に登録。rust-alc-api パターン)
- `secrets-inventory-runtime-staging` / `secrets-inventory-runtime` SA
  (Cloud Run attached、`roles/secretmanager.viewer` のみ。**JSON key は
  発行しない** — Cloud Run の metadata server + ADC で取る)
- shared secret (32 byte) を Google Secret Manager に格納し、Cloud Run が
  起動時に env var `INVENTORY_API_KEY` として参照
- 同値を Cloudflare Secrets Store にも投入 (`SECRETS_INVENTORY_GCP_PROXY_API_KEY`)

## 開発ルール

- branch / worktree 命名と `Refs #N` 規約: [`CLAUDE.md`](CLAUDE.md) (TBD)
- PR テンプレート: [`.github/pull_request_template.md`](.github/pull_request_template.md) (TBD)
- 値は一切扱わない。**メタデータのみ read**
- write 系 (create / update / delete) は実装しない
