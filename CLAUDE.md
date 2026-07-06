# CLAUDE.md

Claude Code 向けの本リポジトリ作業ルール。詳細・IAM 設計・setup コマンドは
`.claude/skills/secrets-inventory-gcp-map/SKILL.md` 参照。

親 repo (`ippoan/secrets-inventory` Worker) から呼ばれる Cloud Run proxy。
値を返す API は実装しない、**メタデータのみ read** + 最小限の reversible
write 例外。staging が実運用、production は `v*` タグ push でのみ deploy。

## Worktree / branch 命名規則

形式: `<issue-number>-<type>-<short-description>` (`type`: feat|fix|refactor|infra)。
issue 番号を持たない branch で実装に入る前に issue を作成し rename すること。

## PR description / commit message のキーワード

- 使用禁止: `Closes #N` / `Fixes #N` / `Resolves #N`
- 使用推奨: `Refs #N` / `Related to #N` / `Part of #N` (release 時に手動 close)

## 方針 (規範のみ。詳細は map skill)

- **GCP の JSON key を一切発行しない**。runtime = attached SA + ADC、
  deploy = WIF (GitHub OIDC trust)。repo secret に GCP key を置かない
- runtime SA IAM は **read-only 基本**、write は reversible な例外
  (SA disable/enable、add-version、create-secret、sync-from-gcp の TTL
  self-grant、cf/gh per-secret accessor、label patch) のみ。delete /
  value read の恒久付与は禁止
- 呼び出しは `X-Inventory-API-Key` (constant-time 比較) 必須
- write 系 body の `value` は log / response に一切 echo しない
- add-version / create-secret の `value` 末尾空白は default 400 reject
  (`X-Allow-Trailing-Whitespace: true` 明示時のみ許可)
- `/cf/*` `/gh/*` の `secretAccessor` は project 全体に付与しない
  (per-secret IAM 限定)

## ローカル開発

```bash
go vet ./...
go test ./...
go build .

# ローカル run (実 GCP を叩く場合は ADC が必要)
gcloud auth application-default login
GCP_PROJECT_ID=your-project INVENTORY_API_KEY=dev-key ./secrets-inventory-gcp
```
