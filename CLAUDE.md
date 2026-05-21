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
- **GCP の JSON key を発行しない**。Cloud Run の attached SA (`secrets-
  inventory-runtime*`) + ADC (metadata server) で credential を取る
- runtime SA に付与する IAM role は `roles/secretmanager.viewer` のみ。
  `accessor` (値の取得) は付けない
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

GitHub Actions + Workload Identity Federation (WIF) 経由のみ。GitHub repo
側に GCP の long-lived JSON key は保存しない。

GCP 側の事前 setup (`secrets-inventory-gcp` issue #1 参照):

- WIF pool + provider (GitHub OIDC trust、subject = `repo:ippoan/secrets-inventory-gcp:*`)
- `cloud-run-deployer` SA (GitHub Actions が借りる)
- `secrets-inventory-runtime` / `secrets-inventory-runtime-staging` SA
  (Cloud Run attached、`roles/secretmanager.viewer` のみ)
- shared secret (32 byte) を Google Secret Manager に格納
- 同値を Cloudflare Secrets Store にも投入 (親 repo 側)

GitHub Actions 側で必要な repository variables (Settings → Secrets and variables → Actions → Variables):

- `GCP_WIF_PROVIDER`: WIF provider full resource name
- `GCP_DEPLOYER_SA`: deployer SA の email
- `GCP_REGION`: deploy region (例: `asia-northeast1`)
- staging: `GCP_PROJECT_ID_STAGING` / `GCP_RUNTIME_SA_STAGING` / `GCP_API_KEY_SECRET_STAGING`
- production: `GCP_PROJECT_ID` / `GCP_RUNTIME_SA` / `GCP_API_KEY_SECRET`

## ローカル開発

```bash
go vet ./...
go test ./...
go build .

# ローカル run (実 GCP を叩く場合は ADC が必要)
gcloud auth application-default login
GCP_PROJECT_ID=your-project INVENTORY_API_KEY=dev-key ./secrets-inventory-gcp
```
