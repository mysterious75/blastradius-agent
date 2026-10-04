"""`blastradius ci` — review and gate entry points for the CI security gate.

Two actions share one pipeline (collect -> analyze -> normalize):

- ``review``: analyze only. Writes JSON + Markdown reports. Exit 0 on
  success, 2 on analysis error. Never fails on findings.
- ``gate``: analyze, then let the deterministic policy engine decide.
  Exit 0 = PASS, 1 = POLICY_FAILURE, 2 = ANALYSIS_ERROR.

The LLM never decides the outcome; only ``blastradius.ci.policy`` does.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from blastradius.ci.analyzers import AiReviewAnalyzer, DeterministicAnalyzer
from blastradius.ci.diff import collect_changeset
from blastradius.ci.llm import AnthropicAdapter, LLMProvider, OpenAICompatibleAdapter
from blastradius.ci.models import ANALYSIS_ERROR, PASS, ChangeSet, GateResult, Policy
from blastradius.ci.notify import notify_gate
from blastradius.ci.policy import evaluate
from blastradius.ci.redact import redact_secrets
from blastradius.ci.reporting import (
    append_github_summary,
    render_markdown,
    write_json,
    write_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="blastradius-ci",
        description="BlastRadius CI security & quality gate (deterministic policy decides PASS/FAIL)",
    )
    sub = ap.add_subparsers(dest="action", required=True)

    for name in ("review", "gate"):
        p = sub.add_parser(name, help=f"{name} the change set")
        p.add_argument("--repo", default=".", help="repo checkout to diff/scan")
        p.add_argument("--base", default="origin/main", help="base ref for git diff")
        p.add_argument("--head", default="HEAD", help="head ref for git diff")
        p.add_argument("--diff-file", default=None, help="unified diff file (offline/tests)")
        p.add_argument("--policy", default=None, help="policy YAML (default: built-in safe policy)")
        p.add_argument(
            "--exclude",
            action="append",
            default=[],
            help="extra exclusion regex for changed paths (repeatable)",
        )
        p.add_argument(
            "--no-ai",
            action="store_true",
            help="skip AI review; deterministic analyzers only",
        )
        p.add_argument(
            "--ai-provider",
            default="anthropic",
            choices=["anthropic", "openai-compatible"],
            help="AI adapter to use when --no-ai is not set",
        )
        p.add_argument("--out", default="ci-gate", help="report output directory")
        p.add_argument(
            "--notify",
            action="store_true",
            help="send the gate summary to configured notification channels",
        )
        p.add_argument("--run-ref", default="", help="CI run reference for reports/notifications")
    return ap


def _select_provider(ai_provider: str, no_ai: bool) -> Optional[LLMProvider]:
    if no_ai:
        return None
    if ai_provider == "openai-compatible":
        return OpenAICompatibleAdapter()
    return AnthropicAdapter()


def run_review(args) -> tuple[GateResult | None, List, List[str], List[str], ChangeSet, Policy]:
    """Collect + analyze.

    Returns (None, findings, errors, warnings, changeset, policy).
    ``review`` never evaluates policy; callers use the findings directly.
    Analysis errors are returned (not raised) so the caller can report them.
    """
    from blastradius.ci.policy import load_policy as _load

    try:
        policy, policy_warnings = _load(args.policy)
    except ValueError as exc:
        return None, [], [f"invalid policy: {exc}"], [], ChangeSet(), Policy()
    changeset, collect_errors = collect_changeset(
        repo=args.repo,
        base=args.base,
        head=args.head,
        diff_file=args.diff_file,
        policy=policy,
        excludes=args.exclude or None,
    )
    errors = list(collect_errors)
    warnings = list(policy_warnings)
    findings = []
    if changeset.truncated:
        errors.append(f"oversized change set: {changeset.truncation_reason}")
    else:
        outcome = DeterministicAnalyzer(repo=args.repo).analyze(changeset)
        findings.extend(outcome.findings)
        errors.extend(outcome.errors)
        warnings.extend(outcome.warnings)
        provider = _select_provider(args.ai_provider, args.no_ai)
        if provider is not None and not provider.is_configured():
            # Missing optional credentials: degrade VISIBLY to
            # deterministic-only mode instead of erroring. Genuine call
            # failures (key present but unusable) still raise inside
            # review() and stay fail-closed.
            warnings.append(
                f"AI review skipped: no credentials configured for "
                f"'{provider.name}' — running deterministic-only "
                f"(set ANTHROPIC_API_KEY to enable)"
            )
            print(
                f"[!] AI review skipped (no credentials for '{provider.name}'); "
                f"deterministic-only mode"
            )
            provider = None
        if provider is not None:
            ai_outcome = AiReviewAnalyzer(provider=provider).analyze(changeset)
            findings.extend(ai_outcome.findings)
            errors.extend(ai_outcome.errors)
            warnings.extend(ai_outcome.warnings)
    return None, findings, errors, warnings, changeset, policy


def _write_reports(result: GateResult, out_dir: str, run_ref: str) -> tuple[str, str]:
    out = Path(out_dir)
    json_path = write_json(result, str(out / "ci-gate.json"), {"run_ref": run_ref})
    markdown = render_markdown(result, {"run_ref": run_ref})
    md_path = write_markdown(result, str(out / "ci-gate.md"), {"run_ref": run_ref})
    append_github_summary(markdown)
    return json_path, md_path


def cmd_review(args) -> int:
    _, findings, errors, review_warnings, changeset, policy = run_review(args)
    metadata = {
        "files": len(changeset.files),
        "excluded": changeset.excluded,
        "truncated": changeset.truncated,
    }
    result = evaluate(findings, policy, errors=errors, metadata=metadata)
    # review action reports analysis; policy outcome is informational here.
    from blastradius.ci.models import Status

    review_status = (
        Status.ANALYSIS_ERROR if result.errors and policy.on_error == "fail-closed" else Status.PASS
    )
    review_result = GateResult(
        status=review_status,
        exit_code=ANALYSIS_ERROR if review_status == Status.ANALYSIS_ERROR else PASS,
        failing=[],
        reported=result.failing + result.reported,
        errors=result.errors,
        warnings=list(review_warnings) + list(result.warnings),
        policy=policy,
        metadata=metadata,
    )
    json_path, md_path = _write_reports(review_result, args.out, args.run_ref)
    print(f"[*] review: {len(findings)} finding(s), {len(errors)} error(s)")
    print(f"[*] wrote {json_path} and {md_path}")
    if args.notify:
        note = notify_gate(review_result, md_path, args.run_ref)
        print(f"[*] notify: channels={note.channels} errors={note.errors}")
    return review_result.exit_code


def cmd_gate(args) -> int:
    _, findings, errors, gate_warnings, changeset, policy = run_review(args)
    metadata = {
        "files": len(changeset.files),
        "excluded": changeset.excluded,
        "truncated": changeset.truncated,
    }
    result = evaluate(findings, policy, errors=errors, metadata=metadata)
    result.warnings = list(gate_warnings) + list(result.warnings)
    json_path, md_path = _write_reports(result, args.out, args.run_ref)
    print(
        f"[*] gate: {result.status.value} "
        f"({len(result.failing)} failing, {len(result.reported)} reported)"
    )
    print(f"[*] wrote {json_path} and {md_path}")
    if args.notify:
        note = notify_gate(result, md_path, args.run_ref)
        print(f"[*] notify: channels={note.channels} errors={note.errors}")
    return result.exit_code


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "review":
            return cmd_review(args)
        return cmd_gate(args)
    except Exception as exc:  # last-resort guard: errors exit 2, never 0-by-accident
        print(f"[!] CI gate execution error: {redact_secrets(str(exc))}", file=sys.stderr)
        return ANALYSIS_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
