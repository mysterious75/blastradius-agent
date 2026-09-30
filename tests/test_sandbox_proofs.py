"""Sandbox PoC proof tests — reconstructions must define target() and templates
must confirm exploitability (offline subprocess mode, no Docker needed)."""

import pytest

from blastradius.hunter.scanner import Finding, reconstruct_target_code
from blastradius.sandbox.generator import _TEMPLATE_FILES, VALID_VULN_TYPES, generate_exploit
from blastradius.tools.sandbox_tool import run_exploit_sandbox


def _finding(vuln_type):
    return Finding(
        file="t.py",
        line=1,
        vuln_type=vuln_type,
        payload="x",
        confidence=0.9,
        severity="HIGH",
        cwe="CWE-1",
        description="d",
        remediation="r",
    )


def test_xxe_template_registered():
    assert "xxe" in VALID_VULN_TYPES
    assert "nosqli" in VALID_VULN_TYPES
    assert _TEMPLATE_FILES["xxe"].endswith(".template")
    assert _TEMPLATE_FILES["nosqli"].endswith(".template")


def test_reconstructions_define_target():
    for vt in ("ssti", "xxe", "nosqli"):
        code = reconstruct_target_code(_finding(vt))
        ns = {}
        exec(compile(code, "<t>", "exec"), ns)
        assert callable(ns.get("target")), f"{vt} reconstruction has no target()"


def test_ssti_proven():
    out = run_exploit_sandbox("ssti", reconstruct_target_code(_finding("ssti")))
    assert out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in out


def test_xxe_proven():
    out = run_exploit_sandbox("xxe", reconstruct_target_code(_finding("xxe")))
    assert out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in out


def test_nosqli_proven():
    out = run_exploit_sandbox("nosqli", reconstruct_target_code(_finding("nosqli")))
    assert out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in out


def test_safe_code_not_proven():
    safe = "def target(user_input):\n    return 'denied'\n"
    for vt in ("ssti", "xxe", "nosqli"):
        out = run_exploit_sandbox(vt, safe)
        assert out.startswith("NOT_EXPLOITABLE"), vt


def test_generate_exploit_rejects_unknown():
    with pytest.raises(ValueError):
        generate_exploit("no-such-type", "x")
