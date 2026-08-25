#!/usr/bin/env python3
"""verifier-integrity-check v0 — 検証ゲートが「緑」を捏造していないか診断する。

読み取りのみ。リポジトリを変更しない。

  A. 必須チェックの穴   required status check に指定したジョブが、job レベルの
                        if: でスキップされうるか。スキップされたジョブは Success
                        として報告され、required であってもマージを妨げない。
  B. 緑を作る経路       失敗または未実行を、無条件に成功へ変換している箇所。
                        continue-on-error / || true / --exit-zero など。

このツール自身も「緑」と「未装備」を区別する。
確認できなかったことを緑として報告しない。

  exit 0  指摘なし・すべて確認できた
  exit 1  指摘あり
  exit 3  指摘はないが、確認できなかった検査がある(未装備)

使い方:
  python check/verifier_integrity_check.py [リポジトリのパス]
  python check/verifier_integrity_check.py --selftest
"""
import json
import re
import subprocess
import sys
from pathlib import Path

UNARMED = 3

# --- B. 「緑を作る経路」の検出パターン -------------------------------------
# (正規表現, 何が起きるか)
GREEN_MAKERS = [
    (r"continue-on-error:\s*true",
     "失敗しても成功として扱われる"),
    (r"\|\|\s*(true|:|exit\s+0)\b",
     "失敗が握りつぶされる"),
    (r"\|\|\s*echo\b",
     "失敗がメッセージに置き換わる"),
    (r"--exit-zero\b",
     "静的解析が指摘を出しても成功で終わる(ruff / flake8)"),
    (r"--passWithNoTests\b",
     "テストが0件でも成功する(jest)"),
    (r"\bset\s+\+e\b",
     "以降の失敗で停止しなくなる"),
    (r"if\s+\[\s*-[a-z]\s+[^\]]+\]\s*;\s*then.*else\s+echo",
     "条件が揃わないと検証せずメッセージだけ出して成功する"),
]

SCAN_GLOBS = [".github/workflows/*.yml", ".github/workflows/*.yaml",
              "Makefile", "makefile", "scripts/*.sh"]


class Result:
    def __init__(self) -> None:
        self.findings: list[str] = []
        self.unarmed: list[str] = []
        self.notes: list[str] = []


# --- 共通 ------------------------------------------------------------------

def load_yaml(path: Path):
    try:
        import yaml
    except ModuleNotFoundError:
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def gh_json(args: list[str], cwd: Path):
    """gh を叩く。gh が無い・権限が無い・404 なら None。

    cwd を渡すのは、gh がリポジトリを作業ディレクトリから推測するため。
    """
    try:
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, cwd=cwd)
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout or "null")
    except json.JSONDecodeError:
        return None


def workflow_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml"):
        out += sorted(root.glob(pattern))
    return out


# --- A. 必須チェックの穴 ---------------------------------------------------

def required_contexts(root: Path, res: Result) -> set[str] | None:
    """実際に強制されている必須チェック名を返す。判定できなければ None(未装備)。

    保護には2系統ある。両方を見ないと「保護が無い」と誤判定する。
      - 旧: branch protection  /repos/{r}/branches/{b}/protection
      - 新: rulesets           /repos/{r}/rules/branches/{b}(有効なルールのみ)

    さらに ruleset には enforcement が active / evaluate / disabled の3状態が
    あり、active 以外は**画面上は設定済みに見えるが強制されていない**。
    """
    slug = gh_json(["repo", "view", "--json",
                    "nameWithOwner,defaultBranchRef,viewerPermission",
                    "-q", "{n:.nameWithOwner,b:.defaultBranchRef.name,"
                          "p:.viewerPermission}"], root)
    if not slug:
        res.unarmed.append(
            "A: リポジトリを特定できない(gh が無い、未認証、または GitHub 上に無い)")
        return None
    repo, branch = slug["n"], slug["b"]
    where = f"{repo}@{branch}"
    admin = slug.get("p") == "ADMIN"
    names: set[str] = set()
    seen_any = False

    # 旧 branch protection
    prot = gh_json(["api", f"repos/{repo}/branches/{branch}/protection"], root)
    if prot is not None:
        seen_any = True
        checks = prot.get("required_status_checks") or {}
        names |= set(checks.get("contexts") or [])
        names |= {c["context"] for c in (checks.get("checks") or []) if c.get("context")}

    # rulesets（有効なルールのみが返る）
    rules = gh_json(["api", f"repos/{repo}/rules/branches/{branch}"], root)
    if rules is not None:
        seen_any = True
        for rule in rules:
            if rule.get("type") != "required_status_checks":
                continue
            params = rule.get("parameters") or {}
            names |= {c["context"]
                      for c in (params.get("required_status_checks") or [])
                      if c.get("context")}

    # 「設定済みに見えるが強制していない」ruleset を検出する。
    # 画面では Active と表示されていても、次のどれかで実質無効になる。
    GATING = {"required_status_checks", "pull_request", "required_signatures",
              "required_deployments", "required_linear_history"}
    for rs in (gh_json(["api", f"repos/{repo}/rulesets"], root) or []):
        if rs.get("target") != "branch":
            continue
        name = rs.get("name")
        if rs.get("enforcement") != "active":
            res.findings.append(
                f"ruleset '{name}' は enforcement={rs.get('enforcement')}。"
                "設定済みに見えるが、何も強制していない")
            print(f"   ✗ ruleset '{name}' — enforcement={rs.get('enforcement')}")
            continue
        detail = gh_json(["api", f"repos/{repo}/rulesets/{rs.get('id')}"], root)
        if not detail:
            continue
        include = ((detail.get("conditions") or {}).get("ref_name") or {}).get("include") or []
        if not include:
            res.findings.append(
                f"ruleset '{name}' は active だが対象ブランチ(conditions.ref_name.include)が"
                "空。どのブランチにも適用されていない")
            print(f"   ✗ ruleset '{name}' — active だが対象ブランチが空")
            continue
        kinds = {r.get("type") for r in (detail.get("rules") or [])}
        if not (kinds & GATING):
            res.findings.append(
                f"ruleset '{name}' に検証を要求するルールが無い"
                f"(現在: {', '.join(sorted(kinds)) or 'なし'})。"
                "削除や強制pushは防げるが、CIの結果はマージ可否に影響しない")
            print(f"   ✗ ruleset '{name}' — 検証を要求するルールが無い"
                  f"({', '.join(sorted(kinds)) or 'なし'})")
        bypass = [f"{b.get('actor_type')}/{b.get('bypass_mode')}"
                  for b in (detail.get("bypass_actors") or [])]
        if bypass:
            res.notes.append(f"ruleset '{name}' の bypass: {', '.join(bypass)}")

    if not seen_any and not admin:
        res.unarmed.append(f"A: {where} の保護設定を読む権限が無い"
                           f"(viewerPermission={slug.get('p')})")
        return None
    if not names:
        res.findings.append(
            f"{where} に有効な必須チェックが無い。"
            "CIが赤でも、そのままマージできる")
        print(f"   ✗ {where} — 有効な必須チェックが無い")
    return names


def conditional_jobs(root: Path, res: Result) -> dict[str, tuple[Path, bool]] | None:
    """job レベル if: を持つジョブ -> (ファイル, 集約ジョブか)。

    集約ジョブ(always() と needs を併用)は、この穴に対する既知の回避策なので
    区別する。
    """
    files = workflow_files(root)
    if not files:
        res.notes.append("A: .github/workflows/ にワークフローが無い")
        return {}
    found: dict[str, tuple[Path, bool]] = {}
    parsed_any = False
    for path in files:
        doc = load_yaml(path)
        if doc is None:
            continue
        parsed_any = True
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict) or "if" not in job:
                continue
            cond = str(job.get("if", ""))
            aggregate = "always()" in cond and bool(job.get("needs"))
            found[str(job.get("name") or job_id)] = (path, aggregate)
    if not parsed_any:
        res.unarmed.append("A: ワークフローを解析できない(pyyaml が必要: pip install pyyaml)")
        return None
    return found


def check_required_holes(root: Path, res: Result) -> None:
    print("A. 必須チェックの穴")
    required = required_contexts(root, res)
    jobs = conditional_jobs(root, res)
    if required is None or jobs is None:
        print("   → 未装備（確認できなかった）")
        return
    print(f"   必須チェック: {', '.join(sorted(required)) or '(なし)'}")
    print(f"   job レベル if: を持つジョブ: {', '.join(sorted(jobs)) or '(なし)'}")
    holes = 0
    for name, (path, aggregate) in sorted(jobs.items()):
        if name not in required:
            continue
        if aggregate:
            print(f"   ○ {name} — 集約ジョブ(always() + needs)。既知の回避策が入っている")
            continue
        holes += 1
        res.findings.append(
            f"必須チェック '{name}' は job レベルの if: でスキップされうる "
            f"({path.as_posix()})。スキップ時は Success として報告され、マージを妨げない")
        print(f"   ✗ {name} — スキップされうる（{path.as_posix()}）")
    if not holes:
        print("   → 穴なし")


# --- B. 緑を作る経路 -------------------------------------------------------

def check_green_makers(root: Path, res: Result) -> None:
    print("\nB. 緑を作る経路")
    targets: list[Path] = []
    for pattern in SCAN_GLOBS:
        targets += sorted(root.glob(pattern))
    if not targets:
        res.unarmed.append("B: 走査対象のファイルが無い")
        print("   → 未装備（走査対象なし）")
        return
    hits = 0
    for path in targets:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for pattern, why in GREEN_MAKERS:
                if re.search(pattern, line):
                    hits += 1
                    where = f"{path.as_posix()}:{n}"
                    res.findings.append(f"{where} {why} — {line.strip()[:80]}")
                    print(f"   ✗ {where}  {why}")
                    print(f"     {line.strip()[:100]}")
                    break
    print(f"   走査 {len(targets)} ファイル" + ("" if hits else " → 指摘なし"))


# --- selftest --------------------------------------------------------------

def selftest() -> int:
    """検出パターン自体の検査。外部ファイルに依存しない。"""
    cases = [
        ("        continue-on-error: true", True),
        ("      - run: pytest -q || true", True),
        ("      - run: ruff check . --exit-zero", True),
        ("      - run: jest --passWithNoTests", True),
        ("          set +e", True),
        ('          if [ -f pyproject.toml ]; then pytest -q; else echo "skip"; fi', True),
        ("      - run: pytest -q", False),
        ("      - run: ruff check .", False),
        ("      # continue-on-error: true", False),   # コメント行は対象外
    ]
    ng = 0
    for line, expected in cases:
        if line.lstrip().startswith("#"):
            hit = False
        else:
            hit = any(re.search(p, line) for p, _ in GREEN_MAKERS)
        mark = "ok " if hit == expected else "NG "
        if hit != expected:
            ng += 1
        print(f"  {mark}{'検出' if expected else '非検出'}: {line.strip()[:70]}")
    print(f"selftest: {len(cases) - ng}/{len(cases)} 件が期待どおり")
    return 1 if ng else 0


# --- main ------------------------------------------------------------------

def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    argv = sys.argv[1:]
    if "--selftest" in argv:
        return selftest()

    root = Path(argv[0]).resolve() if argv else Path.cwd()
    if not root.is_dir():
        print(f"ERROR: ディレクトリが無い: {root}", file=sys.stderr)
        return 2

    print(f"verifier-integrity-check v0 — {root}\n")
    res = Result()
    check_required_holes(root, res)
    check_green_makers(root, res)

    print("\n" + "-" * 60)
    for note in res.notes:
        print(f"  note: {note}")
    for u in res.unarmed:
        print(f"  未装備: {u}")

    if res.findings:
        print(f"\n結果: 指摘 {len(res.findings)}件 / 未装備 {len(res.unarmed)}件")
        print("  「緑」が「検証して合格した」を意味していない箇所があります。")
        return 1
    if res.unarmed:
        print(f"\n結果: 指摘 0件 / 未装備 {len(res.unarmed)}件")
        print("  確認できなかった検査があります。緑とは報告しません。")
        return UNARMED
    print("\n結果: 指摘なし。すべて確認できました。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
