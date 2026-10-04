"""Verified-PR report rendering — Markdown PR comment body (pure functions)."""

from typing import Any, Dict, List

from blastradius.verified_pr.models import (
    RETEST_FIXED,
    RETEST_STILL_VULNERABLE,
    RETEST_UNVERIFIABLE,
    VERDICT_BLOCK,
    VERDICT_MERGE,
)

_RETEST_MARK = {
    RETEST_FIXED: "🛠️ **verified fixed**",
    RETEST_STILL_VULNERABLE: "🔴 still vulnerable",
    RETEST_UNVERIFIABLE: "⚪ unverifiable",
}

_METHOD_NOTE = {
    "exploit-replay": "exploit-replay",
    "static-rescan": "static-rescan",
    "unverifiable": "",
}


def render_comment(
    repo: str,
    verdict: str,
    new_findings: List[Dict[str, Any]],
    confirmed_keys: set,
    retest_by_key: Dict[tuple, Dict[str, Any]],
    dependency_impact: List[Dict[str, Any]],
    patches: List[Dict[str, Any]],
    baseline_active: bool,
    changed_count=None,
    kev_by_file: Dict[tuple, list] | None = None,
    real_proofs: Dict[tuple, Dict[str, Any]] | None = None,
) -> str:
    """Build the PR comment Markdown for a verified-PR run."""
    kev_by_file = kev_by_file or {}
    real_proofs = real_proofs or {}
    if verdict == VERDICT_MERGE:
        header = "## ✅ BlastRadius Verified PR — MERGE"
    elif verdict == VERDICT_BLOCK:
        header = "## 🔴 BlastRadius Verified PR — BLOCK"
    else:
        header = "## ⚪ BlastRadius Verified PR — ERROR"
    lines = [
        header,
        "",
        f"**Target:** `{repo}`"
        + (
            f" · **diff-scope:** {changed_count} changed file(s)"
            if changed_count
            else " · full-scan (diff unavailable)"
        )
        + (" · **baseline-aware**" if baseline_active else ""),
        "",
    ]
    if verdict == VERDICT_MERGE and not new_findings:
        lines += [
            "✅ **No new candidate findings on this diff — safe to merge.**",
            "",
        ]
    elif verdict == VERDICT_MERGE:
        lines += [
            "✅ **No confirmed findings at gate severity — safe to merge.** "
            "(Candidates below the gate are listed for review.)",
            "",
        ]
    elif verdict == VERDICT_BLOCK:
        lines += [
            "🔴 **Merge blocked:** at least one confirmed exploitable finding "
            "is present in this diff. A re-test of 🛠️ means a proven patch "
            "exists — apply it to the PR and re-run.",
            "",
        ]
    else:
        lines += [
            "⚪ **Verification errored** — treat as blocked until re-run succeeds (fail-closed).",
            "",
        ]

    if new_findings:
        lines += [
            "| Severity | File:Line | Type | CWE | Proven | Re-test |",
            "|---|---|---|---|---|---|",
        ]
        for f in new_findings:
            key = (f["file"], f["line"], f["vuln_type"])
            proof = real_proofs.get(key, {})
            if key not in confirmed_keys:
                proven = "—"
            elif proof.get("real_poc") is True:
                proven = "✅ **exploitable (real-code)**"
            elif proof.get("confirm_method") == "bypass-variant":
                proven = "✅ **exploitable (bypass-variant)**"
            else:
                proven = "✅ exploitable (synthetic)"
            retest = retest_by_key.get(key)
            re_mark = _RETEST_MARK.get((retest or {}).get("status", ""), "—")
            method = _METHOD_NOTE.get((retest or {}).get("method", ""), "")
            if method:
                re_mark += f" ({method})"
            lines.append(
                f"| {f.get('severity', '?')} | `{f['file']}:{f['line']}` | "
                f"{f['vuln_type']} | {f.get('cwe', '')} | {proven} | {re_mark} |"
            )
        lines.append("")
        for f in new_findings:
            key = (f["file"], f["line"], f["vuln_type"])
            for cve in kev_by_file.get(key, []):
                lines.append(
                    f"- ⚠️ Known-exploited CVE — `{f['file']}:{f['line']}` "
                    f"({f['vuln_type']}): evidence: `KEV {cve}`"
                )
        if any(kev_by_file.values()):
            lines.append("")

    if dependency_impact:
        lines += ["### 📦 Dependency impact", ""]
        for dep in dependency_impact:
            old, new = dep["old_version"], dep["new_version"]
            arrow = (
                f"`{old}` → `{new}`"
                if old and new
                else (f"added `{new}`" if new else f"removed `{old}`")
            )
            lines.append(f"- `{dep['manifest']}` **{dep['name']}** ({dep['change']}): {arrow}")
        lines.append("")
    else:
        lines += ["### 📦 Dependency impact", "", "No dependency-manifest changes.", ""]

    shown = [p for p in patches if p.get("diff")]
    if shown:
        lines += [
            "### Suggested patches (re-tested on the patched tree)",
            "",
            "<details>",
            "<summary>View patches</summary>",
            "",
        ]
        for p in shown:
            key = (p["file"], p["line"], p["vuln_type"])
            retest = retest_by_key.get(key, {})
            lines += [
                f"**`{p['file']}:{p['line']}` — {p['vuln_type']}** "
                f"({_RETEST_MARK.get(retest.get('status', ''), 'not re-tested')})",
                "",
                "```diff",
                str(p["diff"]).strip(),
                "```",
                "",
            ]
        lines += ["</details>", ""]

    lines += [
        "> Authorized use only. Confirmed findings carry an executed exploit; "
        "a patch counts only after it is re-tested on the patched tree.",
        "",
    ]
    return "\n".join(lines)
