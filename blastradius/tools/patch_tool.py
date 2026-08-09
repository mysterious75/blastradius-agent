"""CAI function_tool: generate and verify a security patch (Phase 4)."""

import json

from blastradius.hunter.scanner import Finding
from blastradius.patcher.loop import PatchLoop
from blastradius.tools.cai_utils import cai_tool


@cai_tool
def generate_and_verify_patch(vuln_type: str, file_path: str, vulnerable_code: str) -> str:
    """Generate a patch for a vulnerable code snippet and verify it fixes the vulnerability.

    The patch is generated (DeepSeek API, or a rule-based fallback), then
    verified: syntax check, exploit re-run (must no longer succeed), and
    regression tests (must pass). Retries up to 3 times; flagged for human
    review if it cannot reach 100% confidence.

    Args:
        vuln_type: One of "sqli", "xss", "ssrf", "traversal".
        file_path: Path of the vulnerable file (for reporting).
        vulnerable_code: The vulnerable Python source snippet. It should
            define ``def target(user_input) -> str`` so it can be verified.

    Returns:
        JSON summary: patch (diff, explanation, source), verification results,
        attempt count, and whether human review is required.
    """
    finding = Finding(
        file=file_path,
        line=0,
        vuln_type=vuln_type,
        payload=vulnerable_code.splitlines()[0] if vulnerable_code.strip() else "",
        confidence=1.0,
        original_code=vulnerable_code,
    )
    result = PatchLoop().run(finding)
    verification = result.verification
    patch = result.patch
    return json.dumps({
        "needs_human": result.needs_human,
        "attempts": result.attempts,
        "patch": {
            "original_code": patch.original_code,
            "patched_code": patch.patched_code,
            "diff": patch.diff,
            "explanation": patch.explanation,
            "source": patch.source,
        },
        "verification": {
            "syntax_ok": verification.syntax_ok,
            "exploit_fixed": verification.exploit_fixed,
            "tests_pass": verification.tests_pass,
            "confidence": verification.confidence,
            "failure_reasons": verification.failure_reasons,
        },
    }, indent=2)
