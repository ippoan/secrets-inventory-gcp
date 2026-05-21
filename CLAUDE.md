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

GitHub Actions 経由で `google-github-actions/auth@v2` の `credentials_json`
モードを使う。**rust-alc-api 等の既存 ippoan deploy パターンと揃える**。
deployer 用 SA の JSON key を repository secret に保存し、`gcloud run deploy`
を回す。

> 「GCP key 0 個運用」は **runtime credential** (Cloud Run → Secret Manager)
> の話で、Cloud Run の attached SA + ADC により維持される。deploy
> credential (GitHub Actions → GCP) は別の境界で、ここは既存 repo と同じく
> deployer SA の JSON key 方式に揃える。

GCP 側の事前 setup (`secrets-inventory-gcp` issue #1 参照):

- `cloud-run-deployer-staging` / `cloud-run-deployer` SA (deploy 用、JSON
  key を発行して GitHub repo secret に登録)
- `secrets-inventory-runtime-staging` / `secrets-inventory-runtime` SA
  (Cloud Run attached、`roles/secretmanager.viewer` のみ)
- shared secret (32 byte) を Google Secret Manager に格納
- 同値を Cloudflare Secrets Store にも投入 (親 repo 側)

GitHub repo 側に登録するもの (Settings → Secrets and variables → Actions):

**Secrets (encrypted):**

- `GCP_DEPLOY_SA_KEY_STAGING`: staging deployer SA の JSON key (rotation 対象)
- `GCP_DEPLOY_SA_KEY`: production deployer SA の JSON key

**Variables (plain text):**

- `GCP_REGION`: deploy region (例: `asia-northeast1`)
- staging: `GCP_PROJECT_ID_STAGING` / `GCP_RUNTIME_SA_STAGING` / `GCP_API_KEY_SECRET_STAGING`
- production: `GCP_PROJECT_ID` / `GCP_RUNTIME_SA` / `GCP_API_KEY_SECRET`

`vars.GCP_PROJECT_ID_STAGING` / `vars.GCP_PROJECT_ID` が空のあいだは workflow
の deploy job が `if:` で skip される (PR の必須 check は通る)。setup 完了後
に variable を入れた瞬間 deploy が動き始める。

## ローカル開発

```bash
go vet ./...
go test ./...
go build .

# ローカル run (実 GCP を叩く場合は ADC が必要)
gcloud auth application-default login
GCP_PROJECT_ID=your-project INVENTORY_API_KEY=dev-key ./secrets-inventory-gcp
```
