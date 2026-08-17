"""PR security scan for GitHub Actions — diff-scoped, sandbox-verified, merge-gate.

Runs the real pipeline (static scan -> sandbox PoC -> auto-patch) against the
changed files of a pull request, writes:

    <out>/pr-comment.md   Markdown body for the PR comment (findings + patches)
    <out>/pr-results.json machine-readable summary (for logs/artifacts)
    <out>/pr-scan.sarif   SARIF 2.1.0 for GitHub code scanning

Exit codes (merge gate): 0 = no confirmed exploitable new findings at/above the
``--fail-on`` severity; 1 = at least one confirmed new finding at/above the
gate severity (the Actions job fails -> PR merge is blocked); 2 = tooling
error.

The scan is diff-scoped against ``--base`` when git history is available
(checkout with ``fetch-depth: 0``). When ``--baseline-ref`` is set, the changed
files are additionally scanned at that baseline revision and only findings NOT
already present in the baseline (matched by file+line+vuln_type) are flagged as
``new_findings``; findings that pre-date the PR stay behind the gate. Sandbox
verification runs each candidate's PoC (Docker ``blastradius-sandbox`` image if
present, else the documented unsandboxed dev fallback for trusted template
PoCs). Only CONFIRMED exploitable new findings count toward the gate.

Usage:
    python scripts/pr_scan.py --repo . --base origin/main --baseline-ref origin/main \\
        --fail-on high --out /tmp/pr-scan
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))  # allow running without pip install

from blastradius.cli.display import RichDisplay  # noqa: E402
from blastradius.cve_hunt import kev_enrichment, load_kev_file  # noqa: E402
from blastradius.export.exporter import FindingsExporter  # noqa: E402
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code  # noqa: E402
from blastradius.tools.sandbox_tool import run_exploit_sandbox  # noqa: E402

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_GATE_CHOICES = ("critical", "high", "medium", "low")


def _finding_dict(f: Finding, annotation: dict | None = None) -> dict:
    d = {
        "file": f.file,
        "line": f.line,
        "vuln_type": f.vuln_type,
        "confidence": f.confidence,
        "severity": f.severity,
        "cwe": f.cwe,
        "description": f.description,
        "remediation": f.remediation,
    }
    if annotation:
        d["kev"] = annotation.get("kev", [])
        d["epss"] = annotation.get("epss", {})
    return d


def _git(repo: str, *args):
    """Run git in ``repo``; returns CompletedProcess (never raises)."""
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


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


def _baseline_findings(
    repo: str, baseline_ref: str, changed_files, min_confidence: float
) -> list[tuple[str, int, str]]:
    """Scan the changed files at ``baseline_ref`` and return (file, line, vuln_type).

    The baseline content for each changed file is materialized via
    ``git show <baseline_ref>:<file>`` into a throwaway temp tree, so the real
    scanners run over it with the same rules. ``file`` is normalized to a POSIX
    repo-relative path so the keys match PR-scan findings. Returns [] when git
    history is unavailable, the baseline scan fails, or nothing was scanned.
    """
    if not baseline_ref or not changed_files:
        return []
    proc = _git(repo, "rev-parse", "--verify", baseline_ref)
    if proc.returncode != 0:
        return []
    tmp = Path(tempfile.mkdtemp(prefix="blastradius-baseline-"))
    try:
        for name in changed_files:
            name = name.replace("\\", "/")
            show = _git(repo, "show", f"{baseline_ref}:{name}")
            if show.returncode != 0:
                continue  # file absent at baseline (added in this PR)
            path = tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(show.stdout, encoding="utf-8")
        if not any(tmp.rglob("*")):
            return []
        hunter = CVEHunter(min_confidence=min_confidence)
        base_findings = hunter.scan_repo(str(tmp))
        return [
            (_normalise_file(f, str(tmp)), f.line, f.vuln_type)
            for f in base_findings
            if _normalise_file(f, str(tmp))
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _normalise_file(f: Finding, repo: str) -> str:
    """Return the finding's file as a POSIX repo-relative path for matching.

    Falls back to the raw POSIX path when the file lives outside ``repo``
    (e.g. a throwaway baseline temp tree whose contents mirror the repo).
    """
    raw = f.file.replace("\\", "/")
    try:
        return Path(raw).resolve().relative_to(Path(repo).resolve()).as_posix()
    except ValueError:
        return raw


def _severity_meets(sev: str, fail_on: str) -> bool:
    """True when ``sev`` is at least as severe as ``fail_on``."""
    return SEVERITY_ORDER.get(str(sev).upper(), 9) <= SEVERITY_ORDER.get(fail_on.upper(), 1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius PR security scan")
    ap.add_argument("--repo", default=".", help="path to the checked-out repo")
    ap.add_argument("--base", default="origin/main", help="base branch ref for diff-scope")
    ap.add_argument(
        "--baseline-ref",
        default="",
        help=(
            "git ref to scan for pre-existing findings (e.g. origin/main). When set, "
            "diff findings already present in the baseline (file+line+vuln_type) are "
            "excluded; empty keeps all diff findings."
        ),
    )
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=_GATE_CHOICES,
        help="exit 1 when a CONFIRMED new finding has severity >= this (default high)",
    )
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument(
        "--kev-file",
        default="",
        help=(
            "path to a CISA KEV JSON snapshot (feed envelope or entry list); "
            "confirmed findings matching a known-exploited CVE are tagged "
            "'kev' (+ 'epss' when --epss-online)"
        ),
    )
    ap.add_argument(
        "--epss-online",
        action="store_true",
        help="fetch FIRST EPSS scores for matched KEV CVEs (online, best-effort, offline-safe)",
    )
    ap.add_argument(
        "--fail-on-kev",
        action="store_true",
        help=(
            "exit 1 when a confirmed finding matches the KEV catalog, regardless "
            "of severity (known-exploited = always block)"
        ),
    )
    ap.add_argument("--out", default="pr-scan", help="output dir (comment/results/sarif)")
    args = ap.parse_args(argv)

    fail_on = args.fail_on.lower()
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

    # Baseline-aware dedup: drop findings that already exist at --baseline-ref.
    baseline_active = bool(args.baseline_ref)
    baseline_keys: set = set()
    if baseline_active:
        baseline_keys.update(
            _baseline_findings(
                args.repo, args.baseline_ref, list(changed or []), args.min_confidence
            )
        )
    new_findings = [
        f
        for f in findings
        if not baseline_active
        or (_normalise_file(f, args.repo), f.line, f.vuln_type) not in baseline_keys
    ]

    confirmed: list[tuple[Finding, str, dict]] = []
    for f in new_findings:
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

    # KEV/EPSS enrichment: tag confirmed findings matching a known-exploited CVE.
    kev_annotation: dict = {}  # id(finding) -> {"kev": [cve ids], "epss": {cve: score}}
    if args.kev_file:
        try:
            kev_entries = load_kev_file(args.kev_file)
        except Exception as exc:
            print(f"[!] could not load --kev-file {args.kev_file}: {exc}")
            kev_entries = []
        if kev_entries:
            for enr in kev_enrichment(
                [f for f, _, _ in confirmed], kev_entries, epss_online=args.epss_online
            ):
                kev_annotation[id(enr["finding"])] = {
                    "kev": list(enr["kev_cves"]),
                    "epss": {
                        cve: row.get("epss", 0.0) for cve, row in (enr.get("epss") or {}).items()
                    },
                }
        if confirmed:
            print(
                f"[kev] {len(kev_annotation)}/{len(confirmed)} confirmed finding(s) "
                f"match known-exploited CVE(s) (epss_online={args.epss_online})"
            )

    # Gate: only CONFIRMED new findings at/above --fail-on count; --fail-on-kev
    # blocks on any confirmed finding that matches the KEV catalog.
    gate_findings = [f for f, _, _ in confirmed if _severity_meets(f.severity, fail_on)]
    kev_blocked = bool(args.fail_on_kev and kev_annotation)
    exit_code = 1 if (gate_findings or kev_blocked) else 0

    comment = _render_comment(
        args.repo, new_findings, confirmed, changed, baseline_active, kev_annotation
    )
    (out_dir / "pr-comment.md").write_text(comment, encoding="utf-8")

    summary = {
        "repo": args.repo,
        "base": args.base,
        "baseline": baseline_active,
        "baseline_ref": args.baseline_ref,
        "fail_on": fail_on,
        "diff_scoped": changed is not None,
        "changed_files": len(changed) if changed else None,
        "candidates": len(findings),
        "new_findings": [_finding_dict(f, kev_annotation.get(id(f))) for f in new_findings],
        "confirmed": len(confirmed),
        "findings": [_finding_dict(f, kev_annotation.get(id(f))) for f in new_findings],
        "patches": [
            {**patch, "file": f.file, "line": f.line, "vuln_type": f.vuln_type}
            for f, _, patch in confirmed
            if patch
        ],
        "kev": {
            "matched_findings": len(kev_annotation),
            "epss_online": args.epss_online,
        },
        "gate": {
            "fail_on": fail_on,
            "confirmed_meeting_gate": len(gate_findings),
            "kev_blocked": kev_blocked,
            "exit_code": exit_code,
        },
    }
    (out_dir / "pr-results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if confirmed:
        FindingsExporter([_finding_dict(f) for f, _, _ in confirmed]).export_sarif(
            str(out_dir / "pr-scan.sarif")
        )

    display = RichDisplay()
    if new_findings:
        display.print_findings_table(new_findings)
    else:
        print("[*] no new candidate findings on the diff")
    print(f"[*] {len(new_findings)} new candidate(s), {len(confirmed)} confirmed exploitable")
    print(f"[gate] {len(gate_findings)} new confirmed finding(s) >= {fail_on} -> exit {exit_code}")
    if args.fail_on_kev:
        print(
            f"[gate] --fail-on-kev: {len(kev_annotation)} confirmed finding(s) match "
            f"known-exploited CVE(s) -> {'exit 1' if kev_blocked else 'no block'}"
        )
    print(
        f"[*] {'baseline-aware (pre-existing findings suppressed)' if baseline_active else 'diff-only (no baseline)'}"
    )
    print(f"[*] comment: {out_dir / 'pr-comment.md'}")

    return exit_code


def _render_comment(
    repo: str,
    findings,
    confirmed,
    changed,
    baseline_active: bool,
    kev_annotation: dict | None = None,
) -> str:
    kev_annotation = kev_annotation or {}
    lines = [
        "## 🔴 BlastRadius PR Security Scan",
        "",
        f"**Target:** `{repo}`"
        + (
            f" · **diff-scope:** {len(changed)} changed file(s)"
            if changed
            else " · full-scan (diff unavailable)"
        )
        + (" · **baseline-aware**" if baseline_active else ""),
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

    # Known-exploited (KEV) annotations under the matching findings.
    kev_lines = []
    for f, _, _ in confirmed:
        ann = kev_annotation.get(id(f))
        if ann:
            kev_lines.append((f, ann))
    if kev_lines:
        lines += ["### ⚠️ Known-exploited CVE", ""]
        for f, ann in kev_lines:
            for cve in ann.get("kev") or []:
                epss = (ann.get("epss") or {}).get(cve)
                evidence = f"KEV {cve}" + (f" (EPSS {epss:.2f})" if epss is not None else "")
                lines.append(
                    f"- ⚠️ Known-exploited CVE — `{f.file}:{f.line}` ({f.vuln_type}): "
                    f"evidence: `{evidence}`"
                )
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
