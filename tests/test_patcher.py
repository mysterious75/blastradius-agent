"""Patch generator/verifier/loop tests — no network, no Docker, no CAI.

The DeepSeek API call is mocked (``_http_post``); everything else runs for
real: rule-based patches, the local sandbox (use_docker=False path), and
pytest in a subprocess.
"""

import json

import pytest

from blastradius.hunter.scanner import Finding
from blastradius.patcher.generator import Patch, PatchGenerator, _RULE_PATCHES
from blastradius.patcher.loop import PatchLoop, PatchResult
from blastradius.patcher.verifier import PatchVerifier, VerificationResult
from blastradius.tools import generate_and_verify_patch

VULN_SQLI_TARGET = '''def target(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input + "'"
'''

PARAMETERIZED_SQLI = '''import sqlite3

def target(user_input):
    conn = sqlite3.connect(":memory:")
    row = conn.execute("SELECT * FROM users WHERE name = ?", (user_input,)).fetchone()
    return str(row)
'''


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """Keep tests hermetic: never hit a real LLM key/endpoint."""
    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)
    monkeypatch.delenv("OPENCODE_MODEL", raising=False)
    monkeypatch.delenv("OPENCODE_BASE_URL", raising=False)


def make_finding(vuln_type="sqli", code=VULN_SQLI_TARGET):
    return Finding(
        file="app.py",
        line=2,
        vuln_type=vuln_type,
        payload='return "SELECT * FROM users WHERE name = \'" + user_input + "\'"',
        confidence=1.0,
        original_code=code,
    )


class FakeGenerator:
    def __init__(self, patches):
        self.patches = list(patches)
        self.calls = []

    def generate_patch(self, finding, failure_context=""):
        self.calls.append(failure_context)
        return self.patches.pop(0)


class FakeVerifier:
    def __init__(self, results):
        self.results = list(results)

    def verify(self, finding, patch):
        return self.results.pop(0)


class FakeSandbox:
    """Records runs; returns a fixed vulnerable flag."""

    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.codes = []

    def run(self, exploit_code, target_code):
        self.codes.append((exploit_code, target_code))
        return {
            "vulnerable": self.vulnerable,
            "output": "[VULNERABLE]" if self.vulnerable else "",
            "error": "",
            "exit_code": 0,
        }


# --- PatchGenerator ----------------------------------------------------------


def test_api_patch_sqli_string_concat_to_parameterized(monkeypatch):
    gen = PatchGenerator(api_key="sk-test")
    canned = {
        "choices": [{"message": {"content": json.dumps({
            "patched_code": PARAMETERIZED_SQLI,
            "explanation": "Replaced string concatenation with a parameterized query.",
        })}}]
    }
    monkeypatch.setattr(
        "blastradius.patcher.generator.PatchGenerator._http_post",
        lambda self, payload: canned,
    )
    patch = gen.generate_patch(make_finding())

    assert patch.source == "api"
    assert patch.explanation == "Replaced string concatenation with a parameterized query."
    assert "?" in patch.patched_code          # parameter placeholder
    assert "execute(" in patch.patched_code
    assert "+ user_input" not in patch.patched_code
    assert patch.original_code == VULN_SQLI_TARGET
    assert patch.diff


def test_api_unavailable_falls_back_to_rule_based(monkeypatch):
    gen = PatchGenerator(api_key="sk-test")

    def boom(self, payload):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("blastradius.patcher.generator.PatchGenerator._http_post", boom)
    patch = gen.generate_patch(make_finding())
    assert patch.source == "rule"


def test_no_api_key_uses_rule_based():
    patch = PatchGenerator(api_key=None).generate_patch(make_finding())
    assert patch.source == "rule"


def test_rule_based_sqli_patch_escapes_input():
    patch = PatchGenerator(api_key=None)._rule_based_patch(make_finding())
    assert patch.source == "rule"
    assert "user_input.replace(\"'\", \"''\")" in patch.patched_code
    assert patch.explanation
    assert patch.diff
    assert patch.diff != ""


def test_patch_diff_is_generated():
    patch = Patch(original_code="a\nb\n", patched_code="a\nc\n")
    assert "-b" in patch.diff
    assert "+c" in patch.diff


# --- PatchVerifier -----------------------------------------------------------


def test_syntax_check():
    assert PatchVerifier.syntax_check("def target(u):\n    return u") is True
    assert PatchVerifier.syntax_check("def target(:\n") is False


def test_exploit_check_uses_patched_code_and_requires_not_vulnerable():
    patch = PatchGenerator(api_key=None)._rule_based_patch(make_finding())
    sandbox = FakeSandbox(vulnerable=False)
    verifier = PatchVerifier(sandbox_runner=sandbox)

    assert verifier.exploit_check(make_finding(), patch) is True
    exploit_code, target_code = sandbox.codes[0]
    assert target_code == patch.patched_code  # sandbox ran the PATCHED code
    assert "TARGET_CODE" in exploit_code


def test_exploit_check_fails_when_still_vulnerable():
    sandbox = FakeSandbox(vulnerable=True)
    verifier = PatchVerifier(sandbox_runner=sandbox)
    noop = Patch(
        original_code=VULN_SQLI_TARGET,
        patched_code=VULN_SQLI_TARGET,
        explanation="noop",
    )
    assert verifier.exploit_check(make_finding(), noop) is False


def test_verify_sqli_rule_patch_all_checks_pass():
    finding = make_finding()
    patch = Patch(
        original_code=finding.original_code,
        patched_code=_RULE_PATCHES["sqli"],
        explanation="rule patch",
    )
    verification = PatchVerifier().verify(finding, patch)

    assert verification.syntax_ok is True
    assert verification.exploit_fixed is True
    assert verification.tests_pass is True
    assert verification.confidence == 100.0
    assert verification.failure_reasons == ""


def test_verify_unpatched_code_remains_exploitable():
    noop = Patch(
        original_code=VULN_SQLI_TARGET,
        patched_code=VULN_SQLI_TARGET,
        explanation="noop",
    )
    verification = PatchVerifier().verify(make_finding(), noop)

    assert verification.syntax_ok is True
    assert verification.exploit_fixed is False
    assert verification.tests_pass is True
    assert verification.confidence == pytest.approx(66.67, abs=0.01)
    assert "exploit" in verification.failure_reasons


# --- PatchLoop ---------------------------------------------------------------


def test_loop_success_on_attempt_1():
    patch = Patch("a", "b", explanation="x")
    gen = FakeGenerator([patch])
    ver = FakeVerifier([VerificationResult(True, True, True, 100.0)])

    result = PatchLoop(generator=gen, verifier=ver).run(make_finding())

    assert result.attempts == 1
    assert result.needs_human is False
    assert result.patch is patch
    assert result.verification.confidence == 100.0


def test_loop_success_on_attempt_2_with_failure_context():
    patch1 = Patch("a", "b", explanation="first")
    patch2 = Patch("a", "c", explanation="second")
    gen = FakeGenerator([patch1, patch2])
    ver = FakeVerifier([
        VerificationResult(True, True, False, 66.67, "regression tests failed"),
        VerificationResult(True, True, True, 100.0),
    ])

    result = PatchLoop(generator=gen, verifier=ver).run(make_finding())

    assert result.attempts == 2
    assert result.needs_human is False
    assert len(gen.calls) == 2
    assert gen.calls[0] == ""
    assert "Attempt 1" in gen.calls[1]


def test_loop_escalates_to_human_after_3_failures():
    patches = [Patch("a", "b", explanation=f"p{i}") for i in range(3)]
    gen = FakeGenerator(patches)
    ver = FakeVerifier([
        VerificationResult(False, False, False, 0.0, "all checks failed"),
    ] * 3)

    result = PatchLoop(generator=gen, verifier=ver).run(make_finding())

    assert result.attempts == 3
    assert result.needs_human is True
    assert len(gen.calls) == 3
    assert "Attempt 2" in gen.calls[2]


def test_loop_end_to_end_rule_based_sqli():
    result = PatchLoop().run(make_finding())

    assert isinstance(result, PatchResult)
    assert result.needs_human is False
    assert result.attempts == 1
    assert result.verification.confidence == 100.0
    assert result.patch.source == "rule"
    assert result.patch.patched_code != result.patch.original_code


# --- CAI tool ----------------------------------------------------------------


def test_generate_and_verify_patch_tool():
    out = generate_and_verify_patch("sqli", "app.py", VULN_SQLI_TARGET)
    data = json.loads(out)

    assert data["needs_human"] is False
    assert data["attempts"] == 1
    assert data["verification"]["confidence"] == 100.0
    assert data["verification"]["syntax_ok"] is True
    assert data["verification"]["exploit_fixed"] is True
    assert data["verification"]["tests_pass"] is True
    assert data["patch"]["diff"]
    assert data["patch"]["patched_code"] != data["patch"]["original_code"]
