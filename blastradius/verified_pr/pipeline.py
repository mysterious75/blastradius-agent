"""Verified-PR pipeline — scan -> prove -> patch -> re-test -> merge/block.

Exit codes: 0 = MERGE (no blocking findings, or every blocking finding is
patched and re-verified fixed); 1 = BLOCK (fail-closed); 2 = tooling error.

The repository itself is never modified: re-testing happens on a scratch
copy. Fix-branch creation stays with ``scripts/autofix_pr.py``.
"""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scripts.pr_scan import (  # single source of truth for diff/gate semantics
    _baseline_findings,
    _changed_files,
    _finding_dict,
    _normalise_file,
    _severity_meets,
)

from blastradius.cve_hunt import kev_enrichment, load_kev_file
from blastradius.ci.redact import redact_secrets
from blastradius.cli.display import RichDisplay
from blastradius.export.exporter import FindingsExporter
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.patcher.loop import PatchLoop
from blastradius.tools.sandbox_tool import run_exploit_sandbox
from blastradius.verified_pr.impact import dependency_impact
from blastradius.verified_pr.models import (
    RETEST_FIXED,
    VERDICT_BLOCK,
    VERDICT_ERROR,
    VERDICT_MERGE,
    VerifiedGate,
    VerifiedReport,
)
from blastradius.verified_pr.replay import (
    extract_harness,
    prove_real_exploit,
    run_bypass_probe,
    supported_types,
)
from blastradius.verified_pr.report import render_comment
from blastradius.verified_pr.retest import retest_patches

_GATE_CHOICES = ("critical", "high", "medium", "low")


def _key(repo: str, f: Finding) -> Tuple[str, int, str]:
    return (_normalise_file(f, repo), f.line, f.vuln_type)


def _evidence_excerpt(sandbox_result: str, max_lines: int = 4) -> str:
    lines = [
        ln.strip()
        for ln in sandbox_result.splitlines()[1:]
        if ln.strip() and not ln.startswith("CONFIRMED")
    ]
    return "\n".join(lines[:max_lines])[:2000]


def decide_verdict(
    gate_keys: List[Tuple[str, int, str]],
    retest_by_key: Dict[Tuple[str, int, str], Dict[str, Any]],
    kev_blocked: bool,
    fail_on: str,
) -> VerifiedGate:
    """Pure gate decision over PR content (fail-closed).

    A confirmed gate finding present in the diff BLOCKS — even when a
    verified fix exists. A fix proven on a scratch tree is evidence the
    *patch* works (handed to reviewers/autofix), never evidence the *PR*
    is safe: only code actually in the diff can unblock. The per-key
    ``retest`` status is reported so reviewers see which findings already
    carry a proven fix.
    """
    fixed = sum(1 for k in gate_keys if (retest_by_key.get(k) or {}).get("status") == RETEST_FIXED)
    blocking = [
        {
            "file": k[0],
            "line": k[1],
            "vuln_type": k[2],
            "retest": (retest_by_key.get(k) or {}).get("status", "NO_PATCH"),
            "fix_verified": (retest_by_key.get(k) or {}).get("status") == RETEST_FIXED,
        }
        for k in gate_keys
    ]
    blocked = bool(blocking or kev_blocked)
    return VerifiedGate(
        verdict=VERDICT_BLOCK if blocked else VERDICT_MERGE,
        exit_code=1 if blocked else 0,
        fail_on=fail_on,
        gate_total=len(gate_keys),
        fixed_and_reverified=fixed,
        blocking=blocking,
        kev_blocked=kev_blocked,
    )


def run_verified_pr(
    repo: str,
    base: str,
    baseline_ref: str = "",
    fail_on: str = "high",
    min_confidence: float = 0.7,
    kev_file: str = "",
    epss_online: bool = False,
    fail_on_kev: bool = False,
    with_retest: bool = True,
    out_dir: str = "verified-pr",
) -> Tuple[int, Dict[str, Any]]:
    """Run the full verified-PR loop. Returns (exit_code, summary_dict)."""
    fail_on = fail_on.lower()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    hunter = CVEHunter(min_confidence=min_confidence)
    findings = hunter.scan_repo(repo)

    changed = _changed_files(repo, base)
    if changed:
        changed = {c.replace("\\", "/") for c in changed}
        findings = [
            f
            for f in findings
            if f.file.replace("\\", "/") in changed
            or Path(f.file).name in {Path(c).name for c in changed}
        ]

    baseline_active = bool(baseline_ref)
    baseline_keys: set = set()
    if baseline_active:
        baseline_keys.update(
            _baseline_findings(repo, baseline_ref, list(changed or []), min_confidence)
        )
    new_findings = [
        f for f in findings if not baseline_active or _key(repo, f) not in baseline_keys
    ]

    confirmed: List[Tuple[Finding, str, dict]] = []
    real_proofs: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    confirm_info: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    for f in new_findings:
        # Real-first confirmation: the identical oracle runs against the REAL
        # function (canonical payloads, then mutated bypass variants). Only
        # when no harness exists does the synthetic reconstruction decide.
        # This closes the weak-fix blind spot: a fix that kills the canonical
        # payload but leaves a variant alive still confirms (via bypass).
        sandbox_result = ""
        confirm_method = ""
        proof: Dict[str, Any] = {"real_poc": None, "evidence": ""}
        harness: Optional[str] = None
        if f.vuln_type in supported_types():
            try:
                src = Path(f.file)
                if not src.is_absolute():
                    src = Path(repo) / src
                harness, _reason = extract_harness(src.read_text(encoding="utf-8"), f.line)
                if harness is None:
                    proof = {"real_poc": None, "evidence": _reason}
            except Exception as exc:
                proof = {"real_poc": None, "evidence": f"real-code replay failed: {exc}"}
        if harness is not None:
            try:
                rr = prove_real_exploit(f.vuln_type, harness)
            except Exception as exc:
                rr = None
                proof = {"real_poc": None, "evidence": f"real-code replay failed: {exc}"}
            if rr is not None and rr.real_exploit_shown:
                sandbox_result = f"CONFIRMED_EXPLOITABLE (real code)\n{rr.evidence}"
                confirm_method = "real-code"
                proof = {"real_poc": True, "evidence": rr.evidence}
            else:
                if rr is not None:
                    proof = {"real_poc": False, "evidence": rr.evidence}
                try:
                    verdict, bypass_evidence = run_bypass_probe(f.vuln_type, harness)
                except Exception as exc:
                    verdict, bypass_evidence = "INCONCLUSIVE", f"bypass probe failed: {exc}"
                if verdict == "HIT":
                    sandbox_result = f"CONFIRMED_EXPLOITABLE (bypass variant)\n{bypass_evidence}"
                    confirm_method = "bypass-variant"
        if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
            try:
                sandbox_result = run_exploit_sandbox(f.vuln_type, reconstruct_target_code(f))
            except Exception as exc:
                sandbox_result = f"ERROR {exc}"
            if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
                continue
            confirm_method = "synthetic"
        confirm_info[_key(repo, f)] = {
            "method": confirm_method,
            "evidence": _evidence_excerpt(sandbox_result),
        }
        real_proofs[_key(repo, f)] = proof
        real_proofs[_key(repo, f)]["confirm_method"] = confirm_method
        patch: dict = {}
        try:
            result = PatchLoop().run(f)
            # Unlike the scan gate, every generated patch enters re-test —
            # even needs_human ones. The snippet-level loop verdict is kept
            # as metadata, but the re-test (real exploit replay on the
            # patched tree) is the stronger, deciding evidence.
            if result.patch and result.patch.diff:
                patch = {
                    "diff": result.patch.diff,
                    "original_code": result.patch.original_code,
                    "patched_code": result.patch.patched_code,
                    "source": result.patch.source,
                    "confidence": (result.verification.confidence if result.verification else 0.0),
                    "needs_human": result.needs_human,
                }
        except Exception:
            patch = {}
        confirmed.append((f, sandbox_result, patch))

    # Re-test: apply each patch on a scratch tree, rescan with the same rules.
    retest_items = [
        (f, {**patch, "file": f.file, "line": f.line, "vuln_type": f.vuln_type})
        for f, _, patch in confirmed
        if patch and patch.get("original_code") and patch.get("patched_code")
    ]
    retest_outcomes = retest_patches(repo, retest_items, min_confidence) if with_retest else []
    retest_by_key = {o.key: o.to_dict() for o in retest_outcomes}

    # Dependency impact of the diff (manifest-level, no reachability claims).
    try:
        dep_changes = [d.to_dict() for d in dependency_impact(repo, base)]
    except Exception:
        dep_changes = []

    # KEV enrichment blocks only KEV-matched findings WITHOUT a verified fix.
    kev_keys: Dict[Tuple[str, int, str], list] = {}
    if kev_file:
        try:
            kev_entries = load_kev_file(kev_file)
        except Exception as exc:
            print(f"[!] could not load --kev-file {kev_file}: {exc}")
            kev_entries = []
        if kev_entries:
            for enr in kev_enrichment(
                [f for f, _, _ in confirmed], kev_entries, epss_online=epss_online
            ):
                finding = enr["finding"]
                kev_keys[_key(repo, finding)] = sorted(enr["kev_cves"])
            print(
                f"[kev] {len(kev_keys)}/{len(confirmed)} confirmed finding(s) "
                f"match known-exploited CVE(s) (epss_online={epss_online})"
            )
    # --fail-on-kev blocks on any confirmed KEV-matched finding present in
    # the diff (content-based like the rest of the gate: a scratch-tree fix
    # does not unblock, it only arms the reviewer/autofix with a proven fix).
    kev_blocked = bool(fail_on_kev and kev_keys)

    gate_keys = [_key(repo, f) for f, _, _ in confirmed if _severity_meets(f.severity, fail_on)]
    gate = decide_verdict(gate_keys, retest_by_key, kev_blocked, fail_on)

    confirmed_keys = {_key(repo, f) for f, _, _ in confirmed}
    new_dicts = []
    for f in new_findings:
        d = _finding_dict(f)
        d["file"] = _normalise_file(f, repo)
        ann = kev_keys.get(_key(repo, f))
        if ann:
            d["kev"] = ann
        proof = real_proofs.get(_key(repo, f), {})
        d["real_poc"] = proof.get("real_poc")
        if proof.get("evidence"):
            d["real_poc_evidence"] = proof["evidence"]
        info = confirm_info.get(_key(repo, f), {})
        if info:
            d["confirm_method"] = info["method"]
            if info.get("evidence"):
                d["confirm_evidence"] = info["evidence"]
        new_dicts.append(d)
    patches = [
        {**patch, "file": _normalise_file(f, repo), "line": f.line, "vuln_type": f.vuln_type}
        for f, _, patch in confirmed
        if patch
    ]

    report = VerifiedReport(
        repo=repo,
        base=base,
        baseline=baseline_active,
        fail_on=fail_on,
        diff_scoped=changed is not None,
        changed_files=len(changed) if changed else None,
        candidates=len(findings),
        confirmed=len(confirmed),
        new_findings=new_dicts,
        patches=patches,
        retest=[o.to_dict() for o in retest_outcomes],
        dependency_impact=dep_changes,
        kev_matched=len(kev_keys),
        gate=gate,
    )
    summary = report.to_dict()

    # Secrets must never reach logs, artifacts, or PR comments: finding
    # payloads and patch diffs embed real source lines, which may carry
    # hardcoded credentials. Redact every artifact (GitHub auto-redaction
    # only covers registered secrets, never values discovered in code).
    comment = redact_secrets(
        render_comment(
            repo,
            gate.verdict,
            new_dicts,
            confirmed_keys,
            retest_by_key,
            dep_changes,
            patches,
            baseline_active,
            changed_count=len(changed) if changed else None,
            kev_by_file=kev_keys,
            real_proofs=real_proofs,
        )
    )
    (out / "verified-comment.md").write_text(comment, encoding="utf-8")
    (out / "verified-results.json").write_text(
        redact_secrets(json.dumps(summary, indent=2)), encoding="utf-8"
    )
    if confirmed:
        sarif_path = out / "verified.sarif"
        FindingsExporter([_finding_dict(f) for f, _, _ in confirmed]).export_sarif(str(sarif_path))
        sarif_path.write_text(
            redact_secrets(sarif_path.read_text(encoding="utf-8")), encoding="utf-8"
        )

    display = RichDisplay()
    if new_findings:
        display.print_findings_table(new_findings)
    else:
        print("[*] no new candidate findings on the diff")
    print(f"[*] {len(new_findings)} new candidate(s), {len(confirmed)} confirmed exploitable")
    print(
        f"[*] re-test: {sum(1 for o in retest_outcomes if o.status == RETEST_FIXED)}/"
        f"{len(retest_outcomes)} patch(es) verified fixed on the patched tree"
    )
    print(f"[gate] verdict={gate.verdict} blocking={len(gate.blocking)} -> exit {gate.exit_code}")
    print(f"[*] comment: {out / 'verified-comment.md'}")
    return gate.exit_code, summary


def _post_github_status(repo: str, verdict: str) -> None:
    """Best-effort GitHub commit status for merge blocking (never raises)."""
    import os

    slug = os.getenv("GITHUB_REPOSITORY", "")
    sha_proc = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    sha = sha_proc.stdout.strip() if sha_proc.returncode == 0 else ""
    if not slug or not sha:
        print("[status] GITHUB_REPOSITORY or HEAD sha unavailable; skipping status post")
        return
    state = "success" if verdict == VERDICT_MERGE else "failure"
    description = (
        "BlastRadius: verified, safe to merge"
        if verdict == VERDICT_MERGE
        else "BlastRadius: blocked, unpatched exploitable findings"
    )
    proc = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{slug}/statuses/{sha}",
            "-f",
            f"state={state}",
            "-f",
            "context=blastradius/verified-pr",
            "-f",
            f"description={description}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        print(f"[status] gh api failed: {proc.stderr.strip()[:200]}")
    else:
        print(f"[status] posted {state} for {sha[:12]}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius Verified PR gate")
    ap.add_argument("--repo", default=".", help="path to the checked-out repo")
    ap.add_argument("--base", default="origin/main", help="base branch ref for diff-scope")
    ap.add_argument(
        "--baseline-ref", default="", help="git ref for pre-existing findings (empty = diff-only)"
    )
    ap.add_argument("--fail-on", default="high", choices=_GATE_CHOICES)
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--kev-file", default="")
    ap.add_argument("--epss-online", action="store_true")
    ap.add_argument(
        "--fail-on-kev",
        action="store_true",
        help="block on KEV-matched findings without a verified fix",
    )
    ap.add_argument(
        "--retest",
        dest="retest",
        action="store_true",
        default=True,
        help="re-test patches on the patched tree (default on)",
    )
    ap.add_argument(
        "--no-retest",
        dest="retest",
        action="store_false",
        help="skip re-testing (reduces to a scan gate)",
    )
    ap.add_argument(
        "--notify", action="store_true", help="send the verdict summary via configured channels"
    )
    ap.add_argument(
        "--post-status",
        action="store_true",
        help="post a GitHub commit status (blastradius/verified-pr)",
    )
    ap.add_argument("--out", default="verified-pr", help="output dir")
    args = ap.parse_args(argv)

    try:
        exit_code, summary = run_verified_pr(
            repo=args.repo,
            base=args.base,
            baseline_ref=args.baseline_ref,
            fail_on=args.fail_on,
            min_confidence=args.min_confidence,
            kev_file=args.kev_file,
            epss_online=args.epss_online,
            fail_on_kev=args.fail_on_kev,
            with_retest=args.retest,
            out_dir=args.out,
        )
    except Exception as exc:
        print(f"[verified-pr] ERROR: {exc}")
        return 2

    if args.notify:
        try:
            from blastradius.notify.notifier import Notifier

            gate = summary["gate"]
            Notifier().notify_text(
                f"BlastRadius Verified PR: {gate['verdict']} "
                f"(blocking={len(gate['blocking'])}, "
                f"fixed={gate['fixed_and_reverified']}/{gate['gate_total']}) "
                f"repo={summary['repo']}"
            )
        except Exception as exc:
            print(f"[notify] failed (non-blocking): {exc}")

    if args.post_status:
        try:
            _post_github_status(args.repo, summary["gate"]["verdict"])
        except Exception as exc:
            print(f"[status] failed (non-blocking): {exc}")

    if summary["gate"]["verdict"] == VERDICT_ERROR:
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
