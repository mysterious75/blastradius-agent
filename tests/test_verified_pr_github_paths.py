"""GitHub-PR path validation — the 10-path matrix, executed locally for real.

Each path runs the actual pipeline (no verdict stubbing; only the synthetic
PoC confirm is stubbed where marked, exactly as in test_pr_scan). Paths:

1. vulnerable PR -> BLOCK
2. pipeline's own patch applied -> PASS (genuine fix round-trip)
3. weak patch -> bypass-variant CONFIRM (blind spot closed) + consistent verdict
4. verification unavailable (JS) -> BLOCK
5. clean PR -> PASS
6. out-of-diff vuln -> PASS; line-shift -> conservative re-flag (documented)
7. multiple findings -> gate math (FIXED + UNVERIFIABLE -> BLOCK)
8. tooling error -> exit 2
9. secrets never reach comment/JSON/SARIF
10. workflow least-privilege/static audit (timeout, SHAs, concurrency, no pwn-request shapes)
"""

import json
import subprocess
from pathlib import Path

import pytest

from blastradius.ci.redact import redact_secrets
from blastradius.verified_pr import pipeline

SQLI_LINE = '    q = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
SQLI_FILE = "import sqlite3\ndef search(name):\n" + SQLI_LINE + "    return q\n"
SQLI_PWD_FILE = (
    "import sqlite3\ndef search(name):\n"
    "    q = \"SELECT * FROM c WHERE pwd='hunter2' AND name = '\" + name + \"'\"\n"
    "    return q\n"
)
WEAK_LINE = '    q = "SELECT * FROM users WHERE name = \'" + name.replace("\'", "\'\'") + "\'"\n'
WEAK_FILE = "import sqlite3\ndef search(name):\n" + WEAK_LINE + "    return q\n"
XSS_JS = 'function render(name){\n  document.getElementById("x").innerHTML = name;\n}\n'
OK_PY = "def ok():\n    return 1\n"


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


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


def _run(repo, out, *extra):
    return pipeline.main(
        [
            "--repo",
            str(repo),
            "--base",
            "HEAD~1",
            "--baseline-ref",
            "HEAD~1",
            "--out",
            str(out),
            *extra,
        ]
    )


def _summary(out):
    return json.loads((Path(out) / "verified-results.json").read_text(encoding="utf-8"))


@pytest.fixture
def no_api_keys(monkeypatch):
    for key in (
        "OPENCODE_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "ZHIPU_API_KEY",
        "GROQ_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# 1. vulnerable PR -> BLOCK (fully live, no stubs)
# ---------------------------------------------------------------------------


def test_path1_vulnerable_pr_blocks(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p1",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY, "app.py": SQLI_FILE}],
        ["base", "pr"],
    )
    out = tmp_path / "o1"
    assert _run(repo, out) == 1
    summary = _summary(out)
    assert summary["gate"]["verdict"] == "BLOCK"
    assert summary["new_findings"][0]["real_poc"] is True


# ---------------------------------------------------------------------------
# 2. pipeline's own patch applied -> PASS (genuine round-trip, live)
# ---------------------------------------------------------------------------


def test_path2_own_patch_roundtrip_passes(tmp_path, no_api_keys):
    from scripts.autofix_pr import apply_patches

    from blastradius.verified_pr.retest import _align_entry

    repo = _repo_with(
        tmp_path,
        "p2",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY, "app.py": SQLI_FILE}],
        ["base", "pr"],
    )
    out1 = tmp_path / "o2a"
    assert _run(repo, out1) == 1
    patches = _summary(out1)["patches"]
    assert patches, "pipeline must generate a patch to round-trip"
    entry = _align_entry(Path(repo), patches[0]["file"], patches[0]["line"], dict(patches[0]))
    applied = apply_patches(Path(repo), [entry])
    assert [r["status"] for r in applied] == ["applied"]

    out2 = tmp_path / "o2b"
    assert _run(repo, out2) == 0
    assert _summary(out2)["gate"]["verdict"] == "MERGE"


# ---------------------------------------------------------------------------
# 3. weak patch -> bypass-variant CONFIRM + consistent verdict (live)
# ---------------------------------------------------------------------------


def test_path3_weak_patch_confirmed_via_bypass(tmp_path, no_api_keys):
    """Weak fix committed in the diff: the canonical PoC is dead, but the
    bypass battery still reaches the real sink -> CONFIRMED via
    bypass-variant (the blind spot stays closed). The diff still carries
    the weakness -> BLOCK, with a proven strong fix attached."""
    repo = _repo_with(
        tmp_path,
        "p3",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY, "app.py": WEAK_FILE}],
        ["base", "pr"],
    )
    out = tmp_path / "o3"
    assert _run(repo, out) == 1
    summary = _summary(out)
    assert summary["confirmed"] >= 1
    assert summary["new_findings"][0]["confirm_method"] == "bypass-variant"
    assert "BYPASS_HIT" in summary["new_findings"][0]["confirm_evidence"]
    assert summary["gate"]["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 4. verification unavailable -> BLOCK (live)
# ---------------------------------------------------------------------------


def test_path4_unverifiable_blocks(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p4",
        [
            {"ok.js": "function ok(){ return 1; }\n"},
            {"ok.js": "function ok(){ return 1; }\n", "app.js": XSS_JS},
        ],
        ["base", "pr"],
    )
    out = tmp_path / "o4"
    assert _run(repo, out) == 1
    summary = _summary(out)
    assert summary["gate"]["verdict"] == "BLOCK"
    assert summary["retest"][0]["method"] == "unverifiable"


# ---------------------------------------------------------------------------
# 5. clean PR -> PASS
# ---------------------------------------------------------------------------


def test_path5_clean_pr_passes(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p5",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY + "\n", "b.py": "x = 1\n"}],
        ["base", "pr"],
    )
    out = tmp_path / "o5"
    assert _run(repo, out) == 0
    assert _summary(out)["gate"]["verdict"] == "MERGE"


# ---------------------------------------------------------------------------
# 6. diff scope: out-of-diff vuln ignored; line-shift re-flagged (live)
# ---------------------------------------------------------------------------


def test_path6_out_of_diff_vuln_ignored(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p6",
        [{"app.py": SQLI_FILE}, {"app.py": SQLI_FILE, "b.py": "x = 1\n"}],
        ["base", "pr"],
    )
    out = tmp_path / "o6"
    assert _run(repo, out) == 0
    summary = _summary(out)
    assert summary["candidates"] == 0
    assert summary["gate"]["verdict"] == "MERGE"


def test_path6_line_shift_conservative_reflag(tmp_path, no_api_keys):
    """Same vuln, shifted lines: baseline keys (file+line+type) miss, so the
    finding is treated as new (conservative). --no-retest isolates the
    scope semantics from the fix machinery."""
    shifted = "# c1\n# c2\n" + SQLI_FILE
    repo = _repo_with(
        tmp_path,
        "p6b",
        [{"app.py": SQLI_FILE}, {"app.py": shifted}],
        ["base", "pr"],
    )
    out = tmp_path / "o6b"
    assert _run(repo, out, "--no-retest") == 1
    assert _summary(out)["gate"]["verdict"] == "BLOCK"


# ---------------------------------------------------------------------------
# 7. multiple findings: FIXED + UNVERIFIABLE -> BLOCK with gate math (live)
# ---------------------------------------------------------------------------


def test_path7_multiple_findings_gate_math(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p7",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY, "app.py": SQLI_FILE, "app.js": XSS_JS}],
        ["base", "pr"],
    )
    out = tmp_path / "o7"
    assert _run(repo, out) == 1
    gate = _summary(out)["gate"]
    assert gate["verdict"] == "BLOCK"
    assert gate["gate_total"] == 2
    assert gate["fixed_and_reverified"] == 1
    assert len(gate["blocking"]) == 2
    by_file = {b["file"]: b for b in gate["blocking"]}
    assert set(by_file) == {"app.py", "app.js"}
    assert by_file["app.py"]["fix_verified"] is True
    assert by_file["app.js"]["fix_verified"] is False


# ---------------------------------------------------------------------------
# 8. tooling error -> exit 2
# ---------------------------------------------------------------------------


def test_path8_tooling_error_exit_two(tmp_path):
    out_file = tmp_path / "not-a-dir"
    out_file.write_text("x", encoding="utf-8")
    repo = _repo_with(tmp_path, "p8", [{"a.py": "x=1\n"}], ["only"])
    assert pipeline.main(["--repo", str(repo), "--out", str(out_file)]) == 2


# ---------------------------------------------------------------------------
# 9. secrets never reach artifacts (live)
# ---------------------------------------------------------------------------


def test_path9_secret_redacted_everywhere(tmp_path, no_api_keys):
    repo = _repo_with(
        tmp_path,
        "p9",
        [{"ok.py": OK_PY}, {"ok.py": OK_PY, "app.py": SQLI_PWD_FILE}],
        ["base", "pr"],
    )
    out = tmp_path / "o9"
    _run(repo, out)
    comment = (Path(out) / "verified-comment.md").read_text(encoding="utf-8")
    results = (Path(out) / "verified-results.json").read_text(encoding="utf-8")
    assert "hunter2" not in comment and "hunter2" not in results
    assert "[REDACTED]" in comment and "[REDACTED]" in results
    sarif = Path(out) / "verified.sarif"
    if sarif.is_file():
        body = sarif.read_text(encoding="utf-8")
        assert "hunter2" not in body


def test_path9_redact_patterns_cover_tokens():
    # Values assembled at runtime so no provider-shaped literal is committed.
    aws_example = "AKIA" + "IOSFODNN7EXAMPLE"
    gh_example = "ghp_" + "123456789012345678901234567890123456"
    assert aws_example not in redact_secrets(f"key {aws_example} here")
    assert "[REDACTED]" in redact_secrets(f"key {aws_example} here")
    assert "[REDACTED]" in redact_secrets(f"token {gh_example}")


# ---------------------------------------------------------------------------
# 10. workflow least-privilege/static audit
# ---------------------------------------------------------------------------


def test_path10_workflow_hardening():
    wf = (_repo_root() / ".github" / "workflows" / "verified-pr.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in wf
    for scope in (
        "contents: read",
        "pull-requests: write",
        "security-events: write",
        "statuses: write",
    ):
        assert scope in wf
    assert "timeout-minutes:" in wf
    assert "cancel-in-progress: true" in wf
    uses = [
        ln.strip()
        for ln in wf.splitlines()
        if ln.strip().startswith("- uses:") or ln.strip().startswith("uses:")
    ]
    assert len(uses) >= 4
    import re as _re

    for line in uses:
        assert _re.search(r"@[0-9a-f]{40}( # v\d+)?$", line), line
    assert wf.count("continue-on-error: true") >= 3  # sandbox build + 2 post steps
    assert "BASE_REF:" in wf  # no inline ${{ }} in shell
    # Collect run: script blocks (indented content after a "run:" line) and
    # require zero expression interpolation there (script-injection surface).
    run_lines = []
    in_run = False
    run_indent = 0
    for ln in wf.splitlines():
        stripped = ln.strip()
        if _re.match(r"^run:\s*\|?\s*$", stripped):
            in_run = True
            run_indent = len(ln) - len(ln.lstrip())
            continue
        if in_run:
            if stripped and len(ln) - len(ln.lstrip()) <= run_indent:
                in_run = False
            else:
                run_lines.append(ln)
    assert run_lines, "expected at least one run: block"
    assert "${{" not in "\n".join(run_lines)
