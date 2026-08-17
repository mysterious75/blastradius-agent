"""PR scan tests — diff-aware baseline dedup + severity merge gate.

Offline: builds real local git repos, runs the pr_scan pipeline end-to-end.
The sandbox step is stubbed with a monkeypatched ``run_exploit_sandbox`` so
the tests are deterministic and fast; the gate logic (proof + severity merge)
is what the assertions exercise.
"""

import json
import subprocess

import pytest

from scripts.pr_scan import main

SQLI_LINE = (
    "import sqlite3\ndef search1(name):\n"
    '    q = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return q\n"
)
SQLI_TWO_LINES = SQLI_LINE + (
    '\n\ndef search2(term):\n    q2 = "UPDATE users SET x = \'" + term + "\'"\n    return q2\n'
)
XSS_LINE = 'function render(name){\n  document.getElementById("x").innerHTML = name;\n}\n'
XSS_TWO_LINES = XSS_LINE + (
    '\nfunction render2(term){\n  document.getElementById("y").innerHTML = term;\n}\n'
)


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _repo_with(tmp_path, name, files, messages):
    """Commit ``files[0]`` then ``files[1]`` (each a {filename: content} map)."""
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
def sqli_repo(tmp_path):
    """app.py with a sqli line in commit 1; a SECOND sqli line in commit 2."""
    return _repo_with(
        tmp_path,
        "sqli",
        [{"app.py": SQLI_LINE}, {"app.py": SQLI_TWO_LINES}],
        ["line1", "line2"],
    )


@pytest.fixture
def xss_repo(tmp_path):
    """app.js with an XSS (HIGH) line in commit 1; a second one in commit 2."""
    return _repo_with(
        tmp_path,
        "xss",
        [{"app.js": XSS_LINE}, {"app.js": XSS_TWO_LINES}],
        ["line1", "line2"],
    )


@pytest.fixture
def confirm_all(monkeypatch):
    """Stub the sandbox: every candidate counts as CONFIRMED_EXPLOITABLE."""
    monkeypatch.setattr(
        "scripts.pr_scan.run_exploit_sandbox",
        lambda vuln_type, code: "CONFIRMED_EXPLOITABLE\n",
    )


def _run(repo, out, *extra):
    return main(
        [
            "--repo",
            str(repo),
            "--base",
            "HEAD~1",
            "--out",
            str(out),
            "--fail-on",
            "high",
            *extra,
        ]
    )


def test_baseline_dedup_keeps_only_new_findings(sqli_repo, tmp_path, confirm_all):
    """Diff has both sqli lines but the baseline has line1 -> only line2 is new."""
    out = tmp_path / "out"
    rc = _run(sqli_repo, out, "--baseline-ref", "HEAD~1")

    results = json.loads((out / "pr-results.json").read_text(encoding="utf-8"))
    assert results["baseline"] is True
    new = results["new_findings"]
    assert len(new) == 1, f"expected only the NEW sqli line, got {new}"
    assert new[0]["vuln_type"] == "sqli"
    assert new[0]["line"] == 8  # line 3 is pre-existing in the baseline; line 8 is new
    assert rc == 1  # confirmed new finding (CRITICAL >= high) fails the gate


def test_baseline_dedup_without_baseline_keeps_all_findings(sqli_repo, tmp_path, confirm_all):
    """Without --baseline-ref the scan stays diff-only: both lines are new."""
    out = tmp_path / "out"
    _run(sqli_repo, out)

    results = json.loads((out / "pr-results.json").read_text(encoding="utf-8"))
    assert results["baseline"] is False
    assert len(results["new_findings"]) == 2


def test_baseline_ref_invalid_falls_back_to_diff_only(sqli_repo, tmp_path, confirm_all):
    """An unresolvable --baseline-ref must not crash the scan."""
    out = tmp_path / "out"
    _run(sqli_repo, out, "--baseline-ref", "does-not-exist")

    results = json.loads((out / "pr-results.json").read_text(encoding="utf-8"))
    assert results["baseline"] is True
    assert len(results["new_findings"]) == 2  # no baseline matched -> all diff findings


def test_fail_on_gate_exit_one_for_critical(sqli_repo, tmp_path, confirm_all):
    """A confirmed CRITICAL finding fails both --fail-on high and critical."""
    out_high = tmp_path / "o_high"
    assert (
        main(
            [
                "--repo",
                str(sqli_repo),
                "--base",
                "HEAD~1",
                "--out",
                str(out_high),
                "--fail-on",
                "high",
            ]
        )
        == 1
    )
    out_crit = tmp_path / "o_crit"
    assert (
        main(
            [
                "--repo",
                str(sqli_repo),
                "--base",
                "HEAD~1",
                "--out",
                str(out_crit),
                "--fail-on",
                "critical",
            ]
        )
        == 1
    )  # CRITICAL >= critical
    results = json.loads((out_high / "pr-results.json").read_text(encoding="utf-8"))
    assert results["gate"]["fail_on"] == "high"
    assert results["gate"]["confirmed_meeting_gate"] == 2
    assert results["gate"]["exit_code"] == 1


def test_fail_on_gate_exit_zero_when_only_high(xss_repo, tmp_path, confirm_all):
    """A confirmed HIGH-only finding fails --fail-on high but passes critical."""
    out_high = tmp_path / "o_high"
    assert (
        main(
            [
                "--repo",
                str(xss_repo),
                "--base",
                "HEAD~1",
                "--out",
                str(out_high),
                "--fail-on",
                "high",
            ]
        )
        == 1
    )
    out_crit = tmp_path / "o_crit"
    assert (
        main(
            [
                "--repo",
                str(xss_repo),
                "--base",
                "HEAD~1",
                "--out",
                str(out_crit),
                "--fail-on",
                "critical",
            ]
        )
        == 0
    )  # HIGH < critical
    results = json.loads((out_crit / "pr-results.json").read_text(encoding="utf-8"))
    assert results["gate"]["fail_on"] == "critical"
    assert results["gate"]["confirmed_meeting_gate"] == 0
    assert results["gate"]["exit_code"] == 0


def test_fail_on_gate_ignores_unconfirmed(sqli_repo, tmp_path, monkeypatch):
    """Only CONFIRMED findings count: without confirmation the gate passes."""
    monkeypatch.setattr(
        "scripts.pr_scan.run_exploit_sandbox",
        lambda vuln_type, code: "NOT_EXPLOITABLE\n",
    )
    out = tmp_path / "out"
    assert _run(sqli_repo, out) == 0  # candidates exist but none confirmed

    results = json.loads((out / "pr-results.json").read_text(encoding="utf-8"))
    assert results["confirmed"] == 0
    assert results["gate"]["confirmed_meeting_gate"] == 0
