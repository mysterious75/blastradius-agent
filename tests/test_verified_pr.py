"""Verified-PR tests — gate verdicts, re-test on the patched tree, impact, E2E.

Repo fixtures are real local git repos. The synthetic PoC confirm is stubbed
via monkeypatch in most E2E tests (as in test_pr_scan); the re-test evidence
(exploit replay, bypass battery) always executes for real. One flagship E2E
(test_e2e_merge_via_replay) runs fully live with no stubs at all.
"""

import json
import subprocess
from pathlib import Path

import pytest

from blastradius.hunter.scanner import Finding
from blastradius.verified_pr import pipeline
from blastradius.verified_pr.impact import dependency_impact
from blastradius.verified_pr.models import (
    RETEST_FIXED,
    RETEST_STILL_VULNERABLE,
    RETEST_UNVERIFIABLE,
)
from blastradius.verified_pr.pipeline import decide_verdict
from blastradius.verified_pr.report import render_comment
from blastradius.verified_pr.retest import retest_patches

SQLI_FILE = (
    "import sqlite3\ndef search(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return q\n"
)
# Strict-allowlist fix: blocks every replay payload, preserves benign input.
FIXED_FILE = (
    "import sqlite3\ndef search(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + "".join(c for c in name if c.isalnum() or c in " _-") + "\'"\n'
    "    return q\n"
)
XSS_JS = 'function render(name){\n  document.getElementById("x").innerHTML = name;\n}\n'


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _repo_with(tmp_path, name, files, messages):
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    for content, msg in zip(files, messages):
        for fname, text in content.items():
            (repo / fname).write_text(text, encoding="utf-8")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", msg)
    return repo


@pytest.fixture
def confirm_all(monkeypatch):
    monkeypatch.setattr(
        pipeline, "run_exploit_sandbox", lambda vuln_type, code: "CONFIRMED_EXPLOITABLE\n"
    )


@pytest.fixture
def no_api_keys(monkeypatch):
    """Force the offline rule-based patch path (isolation, not verdicts)."""
    for key in (
        "OPENCODE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "ZHIPU_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def _finding(repo, fname="app.py", line=3, vuln_type="sqli"):
    return Finding(
        file=str(Path(repo) / fname),
        line=line,
        vuln_type=vuln_type,
        payload="p",
        confidence=0.9,
        severity="CRITICAL",
        cwe="CWE-89",
        description="d",
        remediation="r",
        original_code="orig",
    )


# ---------------------------------------------------------------------------
# Gate verdicts (pure function)
# ---------------------------------------------------------------------------


def test_verdict_merge_when_no_gate_findings():
    gate = decide_verdict([], {}, False, "high")
    assert (gate.verdict, gate.exit_code) == ("MERGE", 0)


def test_verdict_blocks_even_when_fix_verified():
    """Content-based gate: a confirmed finding present in the diff BLOCKS,
    even with a proven fix — the fix must land in the diff (cf. path 2)."""
    key = ("app.py", 3, "sqli")
    gate = decide_verdict([key], {key: {"status": RETEST_FIXED}}, False, "high")
    assert (gate.verdict, gate.exit_code, gate.fixed_and_reverified) == ("BLOCK", 1, 1)
    assert gate.blocking[0]["fix_verified"] is True


def test_verdict_block_when_still_vulnerable():
    key = ("app.py", 3, "sqli")
    gate = decide_verdict([key], {key: {"status": RETEST_STILL_VULNERABLE}}, False, "high")
    assert (gate.verdict, gate.exit_code) == ("BLOCK", 1)
    assert len(gate.blocking) == 1


def test_verdict_block_when_no_patch():
    key = ("app.py", 3, "sqli")
    gate = decide_verdict([key], {}, False, "high")
    assert (gate.verdict, gate.exit_code) == ("BLOCK", 1)
    assert gate.blocking[0]["retest"] == "NO_PATCH"


def test_verdict_block_on_unfixed_kev():
    gate = decide_verdict([], {}, True, "high")
    assert (gate.verdict, gate.exit_code) == ("BLOCK", 1)
    assert gate.kev_blocked is True


# ---------------------------------------------------------------------------
# Re-test on the patched tree
# ---------------------------------------------------------------------------


def _patch_entry(repo, fname, original, patched, source="api"):
    return {
        "file": str(Path(repo) / fname),
        "line": 3,
        "vuln_type": "sqli",
        "original_code": original,
        "patched_code": patched,
        "source": source,
    }


def test_retest_fixed_via_exploit_replay(tmp_path):
    """Strict-allowlist patch: real payloads blocked, benign kept — FIXED
    with exploit-replay evidence, not just scanner silence."""
    repo = tmp_path / "fix"
    repo.mkdir()
    (repo / "app.py").write_text(SQLI_FILE, encoding="utf-8")
    f = _finding(repo)
    entry = _patch_entry(repo, "app.py", SQLI_FILE, FIXED_FILE)
    (out,) = retest_patches(str(repo), [(f, entry)])
    assert out.status == RETEST_FIXED
    assert out.method == "exploit-replay"
    assert "bypass" in out.evidence and "benign" in out.evidence
    assert out.introduced == []
    # original repo untouched
    assert (repo / "app.py").read_text(encoding="utf-8") == SQLI_FILE


def test_retest_weak_patch_caught_by_bypass(tmp_path):
    """Quote-doubling defeats the canonical payloads but the bypass battery
    still wins — STILL_VULNERABLE with the hitting payload as evidence."""
    repo = tmp_path / "weak"
    repo.mkdir()
    (repo / "app.py").write_text(SQLI_FILE, encoding="utf-8")
    f = _finding(repo)
    weak_line = 'q = "SELECT * FROM users WHERE name = \'" + name.replace("\'", "\'\'") + "\'"'
    vuln_line = 'q = "SELECT * FROM users WHERE name = \'" + name + "\'"'
    entry = _patch_entry(repo, "app.py", vuln_line, weak_line, source="rule")
    (out,) = retest_patches(str(repo), [(f, entry)])
    assert out.status == RETEST_STILL_VULNERABLE
    assert out.method == "exploit-replay"
    assert "BYPASS_HIT" in out.evidence


def test_retest_still_vulnerable(tmp_path):
    repo = tmp_path / "still"
    repo.mkdir()
    (repo / "app.py").write_text(SQLI_FILE, encoding="utf-8")
    f = _finding(repo)
    still_bad = SQLI_FILE.replace("search", "search2")
    entry = _patch_entry(repo, "app.py", SQLI_FILE, still_bad)
    (out,) = retest_patches(str(repo), [(f, entry)])
    assert out.status == RETEST_STILL_VULNERABLE
    assert out.method == "exploit-replay"
    assert "[VULNERABLE]" in out.evidence


def test_retest_unverifiable_when_no_match(tmp_path):
    repo = tmp_path / "nomatch"
    repo.mkdir()
    (repo / "app.py").write_text(SQLI_FILE, encoding="utf-8")
    f = _finding(repo)
    entry = _patch_entry(repo, "app.py", "nonexistent snippet", FIXED_FILE)
    (out,) = retest_patches(str(repo), [(f, entry)])
    assert out.status == RETEST_UNVERIFIABLE
    assert "not applied" in out.detail


def test_retest_unverifiable_for_generic_rule_template(tmp_path):
    repo = tmp_path / "rule"
    repo.mkdir()
    (repo / "app.py").write_text(SQLI_FILE, encoding="utf-8")
    f = _finding(repo)
    entry = _patch_entry(repo, "app.py", SQLI_FILE, "line1\nline2", source="rule")
    (out,) = retest_patches(str(repo), [(f, entry)])
    assert out.status == RETEST_UNVERIFIABLE


def test_retest_empty_items(tmp_path):
    assert retest_patches(str(tmp_path), []) == []


# ---------------------------------------------------------------------------
# Dependency impact
# ---------------------------------------------------------------------------


def test_dependency_impact_upgrade_and_add(tmp_path):
    repo = _repo_with(
        tmp_path,
        "deps",
        [
            {"requirements.txt": "flask==2.0.0\n"},
            {"requirements.txt": "flask==3.0.0\nrequests==2.31.0\n"},
        ],
        ["base", "head"],
    )
    changes = {c.name: c for c in dependency_impact(str(repo), "HEAD~1")}
    assert changes["flask"].change == "upgraded"
    assert (changes["flask"].old_version, changes["flask"].new_version) == ("2.0.0", "3.0.0")
    assert changes["requests"].change == "added"


def test_dependency_impact_no_manifests(tmp_path):
    repo = _repo_with(tmp_path, "nodeps", [{"a.txt": "x\n"}, {"a.txt": "y\n"}], ["b", "h"])
    assert dependency_impact(str(repo), "HEAD~1") == []


# ---------------------------------------------------------------------------
# Comment rendering
# ---------------------------------------------------------------------------


def test_render_comment_block_and_merge():
    finding = {
        "file": "app.py",
        "line": 3,
        "vuln_type": "sqli",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
    }
    key = ("app.py", 3, "sqli")
    block = render_comment(
        "r", "BLOCK", [finding], {key}, {key: {"status": RETEST_UNVERIFIABLE}}, [], [], False, 1
    )
    assert "BLOCK" in block and "unverifiable" in block
    merge = render_comment("r", "MERGE", [], set(), {}, [], [], True, 0)
    assert "MERGE" in merge and "safe to merge" in merge
    replayed = render_comment(
        "r",
        "MERGE",
        [finding],
        {key},
        {key: {"status": RETEST_FIXED, "method": "exploit-replay"}},
        [],
        [],
        True,
        1,
        real_proofs={key: {"real_poc": True}},
    )
    assert "real-code" in replayed and "exploit-replay" in replayed


# ---------------------------------------------------------------------------
# End-to-end: block on new vuln, merge on fixed diff
# ---------------------------------------------------------------------------


def test_e2e_block_when_patch_cannot_apply(tmp_path, confirm_all, no_api_keys):
    """JS XSS: the generated patch cannot be applied in-file (multi-line
    non-Python guard) and replay has no harness — UNVERIFIABLE blocks."""
    repo = _repo_with(
        tmp_path,
        "pr",
        [
            {"ok.js": "function ok(){ return 1; }\n"},
            {"ok.js": "function ok(){ return 1; }\n", "app.js": XSS_JS},
        ],
        ["base", "pr"],
    )
    out = tmp_path / "vout"
    rc = pipeline.main(
        ["--repo", str(repo), "--base", "HEAD~1", "--baseline-ref", "HEAD~1", "--out", str(out)]
    )
    assert rc == 1
    summary = json.loads((out / "verified-results.json").read_text(encoding="utf-8"))
    assert summary["gate"]["verdict"] == "BLOCK"
    assert summary["confirmed"] >= 1
    assert "BLOCK" in (out / "verified-comment.md").read_text(encoding="utf-8")


def test_e2e_merge_when_diff_fixes_finding(tmp_path, confirm_all):
    repo = _repo_with(
        tmp_path,
        "prfix",
        [{"app.py": SQLI_FILE}, {"app.py": FIXED_FILE}],
        ["base", "fix"],
    )
    out = tmp_path / "vout"
    rc = pipeline.main(
        ["--repo", str(repo), "--base", "HEAD~1", "--baseline-ref", "HEAD~1", "--out", str(out)]
    )
    assert rc == 0
    summary = json.loads((out / "verified-results.json").read_text(encoding="utf-8"))
    assert summary["gate"]["verdict"] == "MERGE"


def test_e2e_block_with_verified_fix_available(tmp_path, no_api_keys):
    """Flagship, NO stubs: real scan flags the sink, the real PoC confirms
    the real function, the rule patch applies in-file, replay proves the
    patch works — yet the PR still BLOCKS, because the vulnerability is
    present in the diff and the fix lives only on a scratch tree.

    Every assertion is on executed evidence; the verdict is derived,
    never hardcoded.
    """
    repo = _repo_with(
        tmp_path,
        "prlive",
        [
            {"ok.py": "def ok():\n    return 1\n"},
            {"ok.py": "def ok():\n    return 1\n", "app.py": SQLI_FILE},
        ],
        ["base", "pr"],
    )
    out = tmp_path / "vout"
    rc = pipeline.main(
        ["--repo", str(repo), "--base", "HEAD~1", "--baseline-ref", "HEAD~1", "--out", str(out)]
    )
    summary = json.loads((out / "verified-results.json").read_text(encoding="utf-8"))

    # 1. genuinely exploitable (real-code pre-patch replay, not synthetic)
    assert summary["confirmed"] >= 1
    assert summary["new_findings"][0]["real_poc"] is True
    assert "[VULNERABLE]" in summary["new_findings"][0]["real_poc_evidence"]

    # 2. the patch genuinely works on the patched tree...
    (retest,) = summary["retest"]
    assert retest["status"] == RETEST_FIXED
    assert retest["method"] == "exploit-replay"
    assert "bypass" in retest["evidence"] and "benign" in retest["evidence"]

    # 3. ...but the PR still blocks: fix-on-scratch is not fix-in-diff.
    assert summary["gate"]["blocking"][0]["fix_verified"] is True
    assert summary["gate"]["verdict"] == "BLOCK"
    assert rc == 1
    comment = (out / "verified-comment.md").read_text(encoding="utf-8")
    assert "real-code" in comment and "exploit-replay" in comment


# ---------------------------------------------------------------------------
# Diff-scoped scanning: identical findings for the scoped files
# ---------------------------------------------------------------------------


def test_scoped_scan_matches_full_scan_filtered(tmp_path):
    """only_files restriction must not change per-file results: scoped
    findings == full-scan findings filtered to the same files. This is the
    property the large-repo optimization relies on."""
    from blastradius.hunter.scanner import CVEHunter

    repo = tmp_path / "scoped"
    repo.mkdir()
    (repo / "a.py").write_text(SQLI_FILE, encoding="utf-8")
    (repo / "b.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "c.js").write_text(
        'function render(name){\n  document.getElementById("x").innerHTML = name;\n}\n',
        encoding="utf-8",
    )

    def key(f):
        return (Path(f.file).name, f.line, f.vuln_type, f.confidence)

    full = {key(f) for f in CVEHunter().scan_repo(str(repo)) if Path(f.file).name != "b.py"}
    scoped = {
        key(f) for f in CVEHunter().scan_repo(str(repo), only_files=["a.py", "c.js"])
    }
    assert scoped == full
    assert scoped, "fixture must produce findings to compare"
    assert CVEHunter().scan_repo(str(repo), only_files=["b.py"]) == []
