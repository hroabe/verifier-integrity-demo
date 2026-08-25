# 観測結果

観測日: 2026-08-25
リポジトリ: `hroabe/verifier-integrity-demo`

## 設定

`main` ブランチの branch protection:

```json
{
  "required_status_checks": { "strict": false, "contexts": ["required-gate"] },
  "enforce_admins": true
}
```

`required-gate` ジョブは、**実行されれば必ず失敗する**（`exit 1`）。したがって、実行されている限りマージは阻止されるはずである。

## 結果

`gh pr view <n> --json mergeable,mergeStateStatus,statusCheckRollup` の出力。

### PR #1 — 対照群（ゲートが実行される）

```json
{
  "checks": [
    { "name": "required-gate", "status": "COMPLETED", "conclusion": "FAILURE" }
  ],
  "mergeStateStatus": "BLOCKED",
  "mergeable": "MERGEABLE"
}
```

必須チェックが実行され、失敗し、`BLOCKED` になった。**期待どおりの挙動。**

### PR #2 — 本題（ゲートがスキップされる）

```json
{
  "checks": [
    { "name": "required-gate", "status": "COMPLETED", "conclusion": "SKIPPED" }
  ],
  "mergeStateStatus": "CLEAN",
  "mergeable": "MERGEABLE"
}
```

必須チェックは **`SKIPPED`**。一度も実行されていない。それにもかかわらず `mergeStateStatus` は **`CLEAN`**、すなわち**マージ可能**である。

## 判定

| | PR #1 | PR #2 |
|---|---|---|
| `required-gate` の結論 | `FAILURE` | **`SKIPPED`** |
| マージ状態 | `BLOCKED` | **`CLEAN`** |
| 実際に検証されたか | された（失敗） | **されていない** |
| マージできるか | できない | **できる** |

**必須チェックに指定したゲートが一度も実行されないまま、PRはマージ可能になる。**

`mergeable` はどちらも `MERGEABLE` だが、これは「コンフリクトがない」という意味でしかない。判別に使えるのは `mergeStateStatus` のほうである。

## 補足: 状態は「緑」として表示される

`SKIPPED` は GitHub のPR画面上、失敗としては扱われない。チェック一覧では中立扱いになり、**マージボタンは緑になる**。

つまり画面を見ている人間には、

- 検証して合格した
- そもそも検証していない

の区別がつかない。

## 再現手順

1. ジョブレベルの `if:` を持つワークフローを用意する
2. そのジョブ名を branch protection の必須チェックに指定する
3. `if:` 条件が偽になるPRを作る（このデモではブランチ名を `skip/` で始めるか、`skip-gate` ラベルを付ける）
4. `gh pr view <n> --json mergeStateStatus` を見る

ラベル方式を使えば、**コードを1行も変えずに、ラベルを付け外しするだけで `BLOCKED` と `CLEAN` が反転する**様子を1つのPR上で観測できる（ワークフローは `labeled` / `unlabeled` でも起動するようにしてある）。

## 自分のリポジトリで確かめる

```bash
# 必須チェックの一覧
gh api repos/OWNER/REPO/branches/main/protection \
  --jq '.required_status_checks.contexts'

# ジョブレベル if: を持つジョブ
grep -n -B2 'if:' .github/workflows/*.yml
```

両者に重なりがあれば、その必須チェックは条件次第で無効になる。
