"""PR security scan for GitHub Actions — diff-scoped, sandbox-verified, merge-gate.

Runs the real pipeline (static scan -> sandbox PoC -> auto-patch) against the
changed files of a pull request, writes:

    <out>/pr-comment.md   Markdown body for the PR comment (findings + patches)
    <out>/pr-results.json machine-readable summary (for logs/artifacts)
    <out>/pr-scan.sarif   SARIF 2.1.0 for GitHub code scanning

Exit codes (merge gate): 0 = no confirmed exploitable findings; 1 = confirmed
findings (the Actions job fails -> PR merge is blocked); 2 = tooling error.

The scan is diff-scoped against ``--base`` when git history is available
(checkout with ``fetch-depth: 0``). Sandbox verification runs each candidate's
PoC (Docker ``blastradius-sandbox`` image if present, else the documented
unsandboxed dev fallback for trusted template PoCs).

Usage:
    python scripts/pr_scan.py --repo . --base origin/main --out /tmp/pr-scan
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))  # allow running without pip install

from blastradius.cli.display import RichDisplay  # noqa: E402
from blastradius.export.exporter import FindingsExporter  # noqa: E402
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code  # noqa: E402
from blastradius.tools.sandbox_tool import run_exploit_sandbox  # noqa: E402

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _changed_files(repo: str, base: str):
    """Best-effort changed-file list (git diff) — None when unavailable."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...HEAD"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
        names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        return names or None
    except Exception:
        return None


def _finding_dict(f: Finding) -> dict:
    return {
        "file": f.file,
        "line": f.line,
        "vuln_type": f.vuln_type,
        "confidence": f.confidence,
        "severity": f.severity,
        "cwe": f.cwe,
        "description": f.description,
        "remediation": f.remediation,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius PR security scan")
    ap.add_argument("--repo", default=".", help="path to the checked-out repo")
    ap.add_argument("--base", default="origin/main", help="base branch ref for diff-scope")
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--out", default="pr-scan", help="output dir (comment/results/sarif)")
    args = ap.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    hunter = CVEHunter(min_confidence=args.min_confidence)
    findings = hunter.scan_repo(args.repo)

    changed = _changed_files(args.repo, args.base)
    if changed:
        changed = {c.replace("\\", "/") for c in changed}
        findings = [
            f
            for f in findings
            if f.file.replace("\\", "/") in changed
            or Path(f.file).name in {Path(c).name for c in changed}
        ]

    confirmed: list[tuple[Finding, str, dict]] = []
    for f in findings:
        try:
            sandbox_result = run_exploit_sandbox(f.vuln_type, reconstruct_target_code(f))
        except Exception as exc:
            sandbox_result = f"ERROR {exc}"
        if sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
            patch: dict = {}
            try:
                from blastradius.patcher.loop import PatchLoop

                result = PatchLoop().run(f)
                if not result.needs_human and result.patch and result.patch.diff:
                    patch = {
                        "diff": result.patch.diff,
                        "original_code": result.patch.original_code,
                        "patched_code": result.patch.patched_code,
                        "source": result.patch.source,
                        "confidence": (
                            result.verification.confidence if result.verification else 0.0
                        ),
                    }
            except Exception:
                patch = {}
            confirmed.append((f, sandbox_result, patch))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.severity).upper(), 9))
    comment = _render_comment(args.repo, findings, confirmed, changed)
    (out_dir / "pr-comment.md").write_text(comment, encoding="utf-8")

    summary = {
        "repo": args.repo,
        "base": args.base,
        "diff_scoped": changed is not None,
        "changed_files": len(changed) if changed else None,
        "candidates": len(findings),
        "confirmed": len(confirmed),
        "findings": [_finding_dict(f) for f in findings],
        "patches": [
            {**patch, "file": f.file, "line": f.line, "vuln_type": f.vuln_type}
            for f, _, patch in confirmed
            if patch
        ],
    }
    (out_dir / "pr-results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if confirmed:
        FindingsExporter([_finding_dict(f) for f, _, _ in confirmed]).export_sarif(
            str(out_dir / "pr-scan.sarif")
        )

    display = RichDisplay()
    if findings:
        display.print_findings_table(findings)
    print(f"[*] {len(findings)} candidate(s), {len(confirmed)} confirmed exploitable")
    print(f"[*] comment: {out_dir / 'pr-comment.md'}")

    return 1 if confirmed else 0


def _render_comment(repo: str, findings, confirmed, changed) -> str:
    lines = [
        "## 🔴 BlastRadius PR Security Scan",
        "",
        f"**Target:** `{repo}`"
        + (
            f" · **diff-scope:** {len(changed)} changed file(s)"
            if changed
            else " · full-scan (diff unavailable)"
        ),
        "",
    ]
    if not findings:
        lines += ["✅ **No candidate findings.**", ""]
        return "\n".join(lines)

    lines += ["| Severity | File:Line | Type | CWE | Confirmed |", "|---|---|---|---|---|"]
    confirmed_map = {(f.file, f.line, f.vuln_type) for f, _, _ in confirmed}
    for f in findings:
        key = (f.file, f.line, f.vuln_type)
        mark = "✅ **exploitable**" if key in confirmed_map else "—"
        lines.append(f"| {f.severity} | `{f.file}:{f.line}` | {f.vuln_type} | {f.cwe} | {mark} |")
    lines.append("")

    if confirmed:
        lines += [
            "### Suggested patches (rule-based, sandbox-re-verified)",
            "",
            "<details>",
            "<summary>View patches</summary>",
            "",
        ]
        for f, _, patch in confirmed:
            if not patch:
                continue
            lines += [
                f"**`{f.file}:{f.line}` — {f.vuln_type}**",
                "",
                "```diff",
                patch["diff"].strip(),
                "```",
                "",
            ]
        lines += ["</details>", ""]

    lines += [
        "> Authorized use only. This scan runs in a sandboxed PoC; candidates are "
        "reported without proof, confirmed findings carry an executed exploit.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
