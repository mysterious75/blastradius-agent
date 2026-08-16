"""PatchVerifier — verifies a patch with three checks.

1. syntax_check    — patched code parses (ast.parse)
2. exploit_check   — the exploit PoC must FAIL against the patched code
                      (SandboxRunner returns NOT vulnerable)
3. regression_check — existing pytest tests against the patched module pass

Note: pytest runs in the local environment (the sandbox image does not ship
pytest); the sandbox is used for the exploit check.
"""

import ast
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from blastradius.hunter.scanner import Finding
from blastradius.patcher.generator import Patch
from blastradius.sandbox.generator import generate_exploit
from blastradius.sandbox.runner import SandboxRunner

_REGRESSION_TEST = """\
import target_patched as t

def test_target_returns_string_for_benign_input():
    result = t.target("alice")
    assert isinstance(result, str)
    assert result

def test_target_handles_malicious_input_without_crashing():
    result = t.target("' OR '1'='1 --")
    assert isinstance(result, str)
"""


@dataclass
class VerificationResult:
    """Outcome of the three verification checks."""

    syntax_ok: bool
    exploit_fixed: bool
    tests_pass: bool
    confidence: float  # (checks_passed / 3) * 100
    failure_reasons: str = ""


class PatchVerifier:
    """Run the verification loop's three checks against a patch."""

    def __init__(
        self,
        sandbox_runner: Optional[SandboxRunner] = None,
        regression_timeout: int = 60,
    ):
        self.sandbox_runner = sandbox_runner or SandboxRunner(allow_unsandboxed=True)
        self.regression_timeout = regression_timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, finding: Finding, patch: Patch) -> VerificationResult:
        """Run all three checks and return the result with confidence."""
        syntax_ok = self.syntax_check(patch.patched_code)
        exploit_fixed = self.exploit_check(finding, patch)
        tests_pass = self.regression_check(patch.patched_code)

        passed = sum((syntax_ok, exploit_fixed, tests_pass))
        confidence = round((passed / 3) * 100, 2)
        reasons = "; ".join(
            label
            for label, ok in (
                ("syntax check failed", syntax_ok),
                ("exploit still succeeds", exploit_fixed),
                ("regression tests failed", tests_pass),
            )
            if not ok
        )
        return VerificationResult(syntax_ok, exploit_fixed, tests_pass, confidence, reasons)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    @staticmethod
    def syntax_check(code: str) -> bool:
        """Check 1: the patched code must be valid Python."""
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    def exploit_check(self, finding: Finding, patch: Patch) -> bool:
        """Check 2: the exploit must NOT succeed against the patched code."""
        try:
            exploit = generate_exploit(finding.vuln_type, patch.patched_code)
        except ValueError:
            # No exploit template for this vuln type (e.g. traversal) — cannot
            # prove it is fixed, so the check does not pass.
            return False
        try:
            result = self.sandbox_runner.run(exploit, patch.patched_code)
        except Exception:
            return False
        return not result["vulnerable"]

    def regression_check(self, patched_code: str) -> bool:
        """Check 3: pytest against the patched module must exit 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "target_patched.py").write_text(patched_code, encoding="utf-8")
            (Path(tmpdir) / "test_patch.py").write_text(_REGRESSION_TEST, encoding="utf-8")
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pytest", "-q", tmpdir],
                    capture_output=True,
                    text=True,
                    timeout=self.regression_timeout,
                )
            except Exception:
                return False
        return proc.returncode == 0
