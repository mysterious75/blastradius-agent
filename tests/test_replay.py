"""Exploit-replay tests — real payloads against real code, no stubs.

Every verdict here emerges from executed PoCs in SandboxRunner: nothing is
stubbed and no verdict is hardcoded. The weak/broken patch cases prove the
verifier can say NO (STILL_VULNERABLE / INCONCLUSIVE), not just YES.
"""

from blastradius.patcher.generator import PatchGenerator, _line_surgical_patch
from blastradius.sandbox.runner import SandboxRunner
from blastradius.verified_pr.replay import (
    BYPASS_PAYLOADS,
    extract_harness,
    prove_real_exploit,
    supported_types,
    verify_fix,
)

SQLI_VULN = (
    "import sqlite3\ndef search1(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return q\n"
)
SQLI_ALLOWLIST = (
    "import sqlite3\ndef search1(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + "".join(c for c in name if c.isalnum() or c in " _-") + "\'"\n'
    "    return q\n"
)
# Weak fix: doubles single quotes but leaves double-quote injection open.
SQLI_WEAK = (
    "import sqlite3\ndef search1(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + name.replace("\'", "\'\'") + "\'"\n'
    "    return q\n"
)
# Broken fix: destroys benign behavior (returns None).
SQLI_BROKEN = "import sqlite3\ndef search1(name):\n    q = None\n    return q\n"
XSS_VULN = 'import html\ndef render(name):\n    return "<html><body>" + name + "</body></html>"\n'
XSS_ESCAPED = (
    "import html\ndef render(name):\n"
    '    return "<html><body>" + html.escape(name) + "</body></html>"\n'
)


def runner():
    # Local fallback (explicit opt-in, same basis as template PoCs); Docker is
    # used automatically when a daemon is reachable.
    return SandboxRunner(allow_unsandboxed=True)


# ---------------------------------------------------------------------------
# Harness extraction
# ---------------------------------------------------------------------------


def test_extract_harness_ok():
    harness, reason = extract_harness(SQLI_VULN, 3)
    assert harness is not None and reason == ""
    assert harness.rstrip().endswith("target = search1")


def test_extract_harness_line_outside_function():
    harness, reason = extract_harness(SQLI_VULN, 1)
    assert harness is None and "not inside" in reason


def test_extract_harness_rejects_top_level_calls():
    code = "import os\nos.chdir('/tmp')\ndef f(name):\n    return name\n"
    harness, reason = extract_harness(code, 4)
    assert harness is None and "outside the replay scope" in reason


def test_extract_harness_rejects_methods():
    code = "class A:\n    def f(self, name):\n        return name\n"
    harness, reason = extract_harness(code, 3)
    assert harness is None and "not inside a module-level" in reason


def test_extract_harness_rejects_unparseable():
    harness, reason = extract_harness("def broken(:\n", 1)
    assert harness is None and "does not parse" in reason


def test_supported_types():
    assert set(supported_types()) == {"sqli", "xss"}
    assert BYPASS_PAYLOADS["sqli"] and BYPASS_PAYLOADS["xss"]


# ---------------------------------------------------------------------------
# Real exploit proof (pre-patch) + fix verification (post-patch)
# ---------------------------------------------------------------------------


def test_pre_patch_real_code_genuinely_exploitable():
    harness, _ = extract_harness(SQLI_VULN, 3)
    result = prove_real_exploit("sqli", harness, runner())
    assert result.real_exploit_shown is True
    assert "[VULNERABLE]" in result.evidence


def test_allowlist_patch_blocks_canonical_and_bypass():
    harness, _ = extract_harness(SQLI_ALLOWLIST, 3)
    result = verify_fix("sqli", harness, runner())
    assert result.status == "BLOCKED"
    assert result.bypass_blocked == result.bypass_total == len(BYPASS_PAYLOADS["sqli"])
    assert result.benign_ok is True
    assert "neutralized" in result.evidence


def test_weak_patch_caught_by_bypass_battery():
    """Quote-doubling blocks the canonical payloads but the double-quote
    variant sails through — the verifier must say STILL_VULNERABLE."""
    harness, _ = extract_harness(SQLI_WEAK, 3)
    result = verify_fix("sqli", harness, runner())
    assert result.status == "STILL_VULNERABLE"
    assert "BYPASS_HIT" in result.evidence
    assert '" OR "1"="1' in result.evidence


def test_broken_patch_is_inconclusive_not_fixed():
    harness, _ = extract_harness(SQLI_BROKEN, 3)
    result = verify_fix("sqli", harness, runner())
    assert result.status == "INCONCLUSIVE"
    assert "benign" in result.evidence.lower()


def test_xss_escape_blocks_template_and_bypass():
    harness, reason = extract_harness(XSS_ESCAPED, 3)
    assert harness is not None, reason
    result = verify_fix("xss", harness, runner())
    assert result.status == "BLOCKED"
    assert result.benign_ok is True


def test_xss_vuln_confirmed_on_real_code():
    harness, _ = extract_harness(XSS_VULN, 3)
    result = prove_real_exploit("xss", harness, runner())
    assert result.real_exploit_shown is True


def test_replay_unsupported_type_is_inconclusive():
    harness, _ = extract_harness(SQLI_VULN, 3)
    result = verify_fix("traversal", harness, runner())
    assert result.status == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# Line-surgical rule patches (deterministic, offline)
# ---------------------------------------------------------------------------


def test_surgical_sqli_is_single_line_allowlist():
    line = 'q = "SELECT * FROM users WHERE name = \'" + name + "\'"'
    patched, explanation = _line_surgical_patch("sqli", line)
    assert "\n" not in patched
    assert ' "".join(c for c in name' in patched
    assert explanation


def test_surgical_sqli_no_match_returns_none():
    assert _line_surgical_patch("sqli", "q = get_query()") is None


def test_surgical_xss_wraps_concat_var():
    line = 'page = "<html>" + name + "</html>"'
    patched, _ = _line_surgical_patch("xss", line)
    assert patched == 'page = "<html>" + html.escape(name) + "</html>"'


def test_surgical_xss_wraps_assignment_var():
    line = 'document.getElementById("x").innerHTML = name;'
    patched, _ = _line_surgical_patch("xss", line)
    assert patched == 'document.getElementById("x").innerHTML = html.escape(name);'


def test_surgical_xss_already_escaped_returns_none():
    assert _line_surgical_patch("xss", "page = html.escape(name)") is None


def test_rule_patch_prefers_surgical_for_single_line():
    from blastradius.hunter.scanner import Finding

    finding = Finding(
        file="app.py",
        line=3,
        vuln_type="sqli",
        payload='q = "SELECT 1" + name',
        confidence=0.9,
    )
    patch = PatchGenerator(api_key=None)._rule_based_patch(finding)
    assert patch.source == "rule"
    assert patch.kind == "line"
    assert "\n" not in patch.patched_code
    assert "isalnum" in patch.patched_code


def test_loop_stops_after_one_attempt_for_line_patch():
    """Line-surgical patches skip snippet retries (the verdict comes from
    re-testing on the patched tree, not from re-running a deterministic
    rule)."""
    from blastradius.hunter.scanner import Finding
    from blastradius.patcher.loop import PatchLoop

    finding = Finding(
        file="app.py",
        line=3,
        vuln_type="sqli",
        payload='q = "SELECT 1" + name',
        confidence=0.9,
    )
    result = PatchLoop(generator=PatchGenerator(api_key=None)).run(finding)
    assert result.patch.kind == "line"
    assert result.attempts == 1
    assert result.needs_human is True  # snippet checks cannot pass by construction
