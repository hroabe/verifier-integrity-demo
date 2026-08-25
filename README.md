# verifier-integrity-demo

**必須チェック（required status check）に指定したジョブがスキップされると、そのPRはマージできてしまう。**

このリポジトリは、その挙動を実際のPRとして観測できる形で残したものです。

---

## 何を示しているか

GitHub Actions は、`if:` 条件で**スキップされたジョブを "Success" として報告します。** そのジョブを branch protection の必須チェックに指定していても、マージは妨げられません。

つまり次が成立します。

```
必須チェックに指定した
      ↓
そのジョブが if: で飛ばされた
      ↓
緑のチェックマークが付く
      ↓
マージできる
```

**「検証して合格した」と「そもそも検証していない」が、同じ緑になります。**

---

## 観測結果

このリポジトリの `required-gate` ジョブは、**実行されれば必ず失敗します**（`exit 1`）。したがって、実行されている限りマージは阻止されるはずです。

`main` ブランチには branch protection がかかっており、`required-gate` が必須チェックに指定されています。

| PR | `skip-gate` ラベル | `required-gate` | マージ可否 |
|---|---|---|---|
| [#1](../../pull/1) | なし | 実行され、**失敗** | **ブロックされる**（期待どおり） |
| [#2](../../pull/2) | あり | **スキップ** | **マージできる** ← 問題 |

PR #2 では、必須チェックに指定したゲートが一度も実行されていません。それでもマージ可能な状態になります。

機械可読な観測結果は [`OBSERVED.md`](OBSERVED.md) に記録してあります。

---

## なぜ job レベルの `if:` なのか

「そんな書き方をしなければいい」という話ではありません。**これは推奨されている書き方です。**

workflow レベルの `paths:` フィルタを使うと、対象外のPRではワークフロー自体が起動しません。すると必須チェックは報告されず、PRは

```
Expected — Waiting for status to be reported
```

で永久に止まります。**マージできなくなります。**

これを避けるための定石が、`paths:` をやめて job レベルの `if:` へ移すことです。GitHub のコミュニティでも繰り返し案内されています。

つまり:

| 書き方 | 対象外のPR | 結果 |
|---|---|---|
| workflow レベル `paths:` | ワークフローが起動しない | **マージできない**（詰まる） |
| **job レベル `if:`** | ジョブがスキップされ Success | **マージできる**（穴が開く） |

**詰まらないようにする唯一の方法が、穴を開けることになっています。**

---

## 回避策（既知）

この問題は知られており、回避策が流通しています。回避策のためのツールが存在すること自体が、基盤の側がこの区別をできていないことを示しています。

- **集約ジョブ** — 個別のジョブを直接必須にせず、`always()` で走る単一の集約ジョブが各ジョブの `result` を検査し、その集約ジョブだけを必須にする
- [`poseidon/wait-for-status-checks`](https://github.com/poseidon/wait-for-status-checks) — 「起動したチェックが通ること」を要求する。GitHub の素朴な「チェックが通ること」と区別している
- GitHub community discussion [#44490](https://github.com/orgs/community/discussions/44490) — path filtering 使用時に必須チェックを fail ではなく pass/skip 扱いにしてほしい、という要望

---

## 自分のリポジトリで確かめる

診断ツールを同梱しています。**読み取りのみで、リポジトリを変更しません。**

```bash
pip install pyyaml
python check/verifier_integrity_check.py /path/to/your/repo
```

2つを見ます。

| | 検査 |
|---|---|
| **A. 必須チェックの穴** | required status check に指定したジョブが、job レベルの `if:` でスキップされうるか。branch protection そのものが無い場合も指摘します |
| **B. 緑を作る経路** | 失敗や未実行を無条件に成功へ変換している箇所。`continue-on-error` / `|| true` / `--exit-zero` / `--passWithNoTests` / `set +e` / シェルの条件付きskip |

出力例（このリポジトリ自身に対して実行した場合）:

```
A. 必須チェックの穴
   必須チェック: required-gate
   job レベル if: を持つジョブ: required-gate
   ✗ required-gate — スキップされうる（.github/workflows/ci.yml）

結果: 指摘 1件 / 未装備 0件
```

**このツール自身も「緑」と「未装備」を区別します。** 権限が無くて branch protection を読めなかったときは、指摘0件でも緑とは報告せず `exit 3`（未装備）を返します。確認していないことを合格として報告しない、というのがこのリポジトリの主張そのものだからです。

| exit | 意味 |
|---|---|
| 0 | 指摘なし・すべて確認できた |
| 1 | 指摘あり |
| 3 | 指摘は無いが、確認できなかった検査がある（未装備） |

検出パターン自体の検査:

```bash
python check/verifier_integrity_check.py --selftest
```

### 手で確かめる場合

```bash
gh api repos/OWNER/REPO/branches/main/protection --jq '.required_status_checks.contexts'
grep -n -B2 'if:' .github/workflows/*.yml
```

両者に重なりがあれば、**その必須チェックは条件次第で無効になります。**

---

## この問題の一般形

これは GitHub Actions 固有のバグではなく、**検証ゲート一般に起きる誤り**の一例です。

> **未装備と合格を、同じ「緑」で報告してしまう。**

同じ誤りは、CIの外側でも起きます。ゲート実行器が未設定のチェックを飛ばして「全ゲート緑」と出力する、参照データが空のまま合格率100%を返す、といった形です。

区別のために必要なのは3つです。

1. **出力で分ける** — 「緑N件 / 未装備M件」と報告し、未装備を機械可読な成果物に残す
2. **失効させる** — 未装備には期限を持たせ、期限を越えたら赤にする
3. **strict モードを持つ** — main ブランチやリリース時は、未装備を赤とする

参照実装: [hroabe/shioji](https://github.com/hroabe/shioji)

---

## ライセンス

MIT
