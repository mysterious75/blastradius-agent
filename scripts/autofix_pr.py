"""Autofix bot-PR — apply BlastRadius patches on a branch and open a fix PR.

Reads the JSON written by ``scripts/pr_scan.py``, switches to a fresh branch
based on the target branch, applies each patch (exact-match + parse-safe
only), commits, pushes, and opens a PR via the ``gh`` CLI. Skipped patches
(ambiguous match, unsafe replacement, generic rule template) are reported and
left for manual review — the bot never edits code it cannot prove.

Safety gates per patch:
  - ``original_code`` must appear exactly once in the file
  - the patched file must still parse (Python) or stay single-line (other langs)
  - generic multi-line rule templates are never applied in-file

Usage:
    python scripts/autofix_pr.py --results pr-scan/pr-results.json \
        --repo . --base main --pr 42
"""

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))  # noqa: E402  (allow running without pip install)


def _repo_relative(repo: Path, file: str) -> Path:
    path = Path(file)
    try:
        return path.relative_to(repo)
    except ValueError:
        return Path(path.name)


def _still_parseable(path: Path, content: str) -> bool:
    if path.suffix.lower() == ".py":
        try:
            ast.parse(content)
            return True
        except SyntaxError:
            return False
    # non-python: only allow single-line replacements (line edits)
    return "\n" not in content


def apply_patches(repo: Path, patches: list[dict]) -> list[dict]:
    """Apply safe patches in place. Returns entries describing each outcome."""
    results = []
    for entry in patches:
        rel = _repo_relative(repo, entry.get("file", ""))
        path = repo / rel
        original = entry.get("original_code", "")
        patched = entry.get("patched_code", "")
        outcome = {
            "file": str(rel),
            "line": entry.get("line"),
            "vuln_type": entry.get("vuln_type"),
            "source": entry.get("source", "rule"),
        }
        if not path.is_file():
            outcome.update(status="skipped", reason="file not found")
            results.append(outcome)
            continue
        if not original or not patched or original == patched:
            outcome.update(status="skipped", reason="empty or no-op patch")
            results.append(outcome)
            continue
        if "\n" in patched and entry.get("source") == "rule":
            outcome.update(status="skipped", reason="generic rule template (manual review)")
            results.append(outcome)
            continue
        content = path.read_text(encoding="utf-8")
        if content.count(original) != 1:
            outcome.update(status="skipped", reason="ambiguous or missing match")
            results.append(outcome)
            continue
        new_content = content.replace(original, patched)
        if not _still_parseable(path, new_content):
            outcome.update(status="skipped", reason="replacement breaks syntax")
            results.append(outcome)
            continue
        path.write_text(new_content, encoding="utf-8")
        outcome.update(status="applied", patched_code=patched)
        results.append(outcome)
    return results


def _run(cmd: list[str], repo: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True, check=check)


def switch_to_fix_branch(repo: Path, base: str, branch: str) -> bool:
    """Move the working tree onto a fresh fix branch off ``base`` (best-effort).

    Returns True when the branch is based on ``origin/<base>``; False when it
    falls back to the current HEAD (e.g. no origin remote locally).
    """
    if base:
        try:
            _run(["git", "fetch", "origin", base], repo)
            _run(["git", "checkout", "-B", branch, f"origin/{base}"], repo)
            return True
        except subprocess.CalledProcessError:
            print(f"[autofix] cannot fetch origin/{base}; basing fix branch on current HEAD")
    _run(["git", "checkout", "-B", branch], repo)
    return False


def push_and_open_pr(
    repo: Path, branch: str, base: str, pr_number: int, applied: list[dict]
) -> str:
    """Push the branch and open a PR via gh. Returns the PR URL or ''."""
    token = os.getenv("GITHUB_TOKEN", "")
    remote = os.getenv("GITHUB_REPOSITORY", "")
    if token and remote:
        push_url = f"https://x-access-token:{token}@github.com/{remote}.git"
        _run(["git", "remote", "set-url", "origin", push_url], repo)
    try:
        _run(["git", "push", "-u", "origin", branch], repo)
    except subprocess.CalledProcessError:
        print("[autofix] git push failed (no credentials?) — branch left local")
        return ""
    if not shutil.which("gh"):
        print(f"[autofix] branch pushed: {branch} — open a PR manually (gh not found)")
        return ""
    title = f"fix: BlastRadius autofix for PR #{pr_number}"
    body = (
        "## 🤖 BlastRadius Autofix\n\n"
        f"Automatically generated from the findings on PR #{pr_number}. "
        "Each change was applied only when the vulnerable line matched exactly "
        "and the file still parses. **Please review before merging.**\n\n"
        "| File | Line | Type |\n|---|---|---|\n"
        + "\n".join(f"| `{r['file']}` | {r['line']} | {r['vuln_type']} |" for r in applied)
        + "\n\n> Authorized use only. Run `python -m pytest tests/ -q` after merging."
    )
    proc = _run(
        ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body],
        repo,
        check=False,
    )
    if proc.returncode == 0:
        return proc.stdout.strip()
    print(f"[autofix] gh pr create failed: {proc.stderr.strip()}")
    return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius autofix bot-PR")
    ap.add_argument("--results", required=True, help="pr-results.json from pr_scan.py")
    ap.add_argument("--repo", default=".", help="checked-out repo path")
    ap.add_argument("--base", default="main", help="base branch for the fix PR")
    ap.add_argument("--pr", type=int, default=0, help="source PR number (naming only)")
    ap.add_argument("--branch-prefix", default="blastradius/autofix")
    args = ap.parse_args(argv)

    data = json.loads(Path(args.results).read_text(encoding="utf-8"))
    patches = data.get("patches", [])
    if not patches:
        print("[autofix] no patches in results — nothing to do")
        return 0

    repo = Path(args.repo).resolve()
    branch = f"{args.branch_prefix}/pr-{args.pr}-autofix"
    switch_to_fix_branch(repo, args.base, branch)

    results = apply_patches(repo, patches)
    applied = [r for r in results if r["status"] == "applied"]
    for r in results:
        print(
            f"[autofix] {r['status']:>8}: {r['file']}:{r['line']} "
            f"({r['vuln_type']}) — {r.get('reason', '')}".rstrip()
        )
    if not applied:
        print("[autofix] no patches applied safely — manual review required")
        return 0

    _run(["git", "add", "-A"], repo)
    files = ", ".join(f"{r['file']}:{r['line']}" for r in applied)
    _run(["git", "commit", "-m", f"fix: BlastRadius autofix for PR #{args.pr} ({files})"], repo)

    url = push_and_open_pr(repo, branch, args.base, args.pr, applied)
    print(f"[autofix] fix branch: {branch}")
    print(f"[autofix] fix PR: {url}" if url else "[autofix] PR not opened (push skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
