"""Sandbox tests — run WITHOUT CAI and WITHOUT a running Docker daemon.

The docker command path is verified with a mocked subprocess; the exploit
templates are executed for real in the runner's local mode
(``use_docker=False``), which is equivalent code being run, minus container
isolation.
"""

import subprocess
from unittest import mock

import pytest

from blastradius.sandbox.generator import generate_exploit
from blastradius.sandbox.runner import SandboxRunner
from blastradius.tools.sandbox_tool import run_exploit_sandbox

# --- Targets -----------------------------------------------------------------

VULN_SQLI = '''
def target(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input + "'"
'''

SAFE_SQLI = '''
def target(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input.replace("'", "''") + "'"
'''

VULN_XSS = '''
def target(user_input):
    return "<html><body>" + user_input + "</body></html>"
'''

SAFE_XSS = '''
import html

def target(user_input):
    return "<html><body>" + html.escape(user_input) + "</body></html>"
'''

VULN_SSRF = '''
def target(user_input):
    return "http://internal-service/fetch?url=" + user_input
'''

SAFE_SSRF = '''
def target(user_input):
    if "169.254" in user_input:
        return "blocked"
    return "http://internal-service/fetch?url=" + user_input
'''


# --- Template generation -----------------------------------------------------


def test_generate_exploit_embeds_target_code():
    exploit = generate_exploit("sqli", VULN_SQLI)
    assert "TARGET_CODE = " in exploit
    assert repr(VULN_SQLI) in exploit
    assert "TARGET_CODE = __TARGET_CODE__" not in exploit  # placeholder rendered


def test_generate_exploit_rejects_unknown_vuln_type():
    with pytest.raises(ValueError, match="Unsupported vuln_type"):
        generate_exploit("rce", VULN_SQLI)


# --- SQLi: the blueprint's SQL string-concatenation case ---------------------


def test_sqli_vulnerable_is_confirmed():
    exploit = generate_exploit("sqli", VULN_SQLI)
    result = SandboxRunner(use_docker=False).run(exploit, VULN_SQLI)
    assert result == {
        "vulnerable": True,
        "output": result["output"],
        "error": "",
        "exit_code": 0,
    }
    assert "[VULNERABLE]" in result["output"]

    tool_out = run_exploit_sandbox("sqli", VULN_SQLI)
    assert tool_out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in tool_out


def test_sqli_parameterized_is_not_vulnerable():
    exploit = generate_exploit("sqli", SAFE_SQLI)
    result = SandboxRunner(use_docker=False).run(exploit, SAFE_SQLI)
    assert result["vulnerable"] is False
    assert "NOT_VULNERABLE" in result["output"]

    tool_out = run_exploit_sandbox("sqli", SAFE_SQLI)
    assert tool_out.startswith("NOT_EXPLOITABLE")


def test_sqli_execute_style_target_confirmed():
    """Execute-style targets (SQL run, no query string returned) must be detected."""
    vuln = """
def target(user_input):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE users (id INTEGER)")
    conn.execute("SELECT * FROM users WHERE id=" + user_input)
    return "ok"
"""
    tool_out = run_exploit_sandbox("sqli", vuln)
    assert tool_out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in tool_out


def test_sqli_execute_parameterized_not_confirmed():
    safe = """
def target(user_input):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE users (id INTEGER)")
    conn.execute("SELECT * FROM users WHERE id=?", (user_input,))
    return "ok"
"""
    assert run_exploit_sandbox("sqli", safe).startswith("NOT_EXPLOITABLE")


# --- Other templates ---------------------------------------------------------


def test_xss_vulnerable_is_confirmed():
    tool_out = run_exploit_sandbox("xss", VULN_XSS)
    assert tool_out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in tool_out


def test_xss_escaped_is_not_vulnerable():
    assert run_exploit_sandbox("xss", SAFE_XSS).startswith("NOT_EXPLOITABLE")


def test_ssrf_vulnerable_is_confirmed():
    tool_out = run_exploit_sandbox("ssrf", VULN_SSRF)
    assert tool_out.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in tool_out


def test_ssrf_blocked_is_not_vulnerable():
    assert run_exploit_sandbox("ssrf", SAFE_SSRF).startswith("NOT_EXPLOITABLE")


def test_sandbox_tool_unknown_vuln_type_returns_not_exploitable():
    # never-crash contract: unknown vuln types return a string, not a raise
    result = run_exploit_sandbox("rce", VULN_SQLI)
    assert result.startswith("NOT_EXPLOITABLE")
    assert "no exploit template" in result


# --- Runner behavior ---------------------------------------------------------


def test_runner_returns_expected_keys():
    result = SandboxRunner(use_docker=False).run(
        "print('hello')", "print('target')"
    )
    assert set(result) == {"vulnerable", "output", "error", "exit_code"}
    assert result["output"] == "hello\n"
    assert result["exit_code"] == 0


def test_runner_reports_timeout():
    slow = "import time\ntime.sleep(60)\n"
    result = SandboxRunner(use_docker=False, timeout=1).run(slow, "")
    assert result["vulnerable"] is False
    assert "timed out" in result["error"]


@mock.patch("blastradius.sandbox.runner.subprocess.run")
def test_docker_command_flags_and_detection(mock_run):
    fake = mock.Mock()
    fake.returncode = 0
    fake.stdout = "exploiting...\n[VULNERABLE] confirmed\n"
    fake.stderr = ""
    mock_run.return_value = fake

    runner = SandboxRunner(use_docker=True, timeout=7, memory_mb=256)
    result = runner.run("print('x')", "print('y')")

    assert result["vulnerable"] is True
    cmd = mock_run.call_args.args[0]
    assert cmd[0] == "docker"
    assert cmd[1:3] == ["run", "--rm"]
    assert "--runtime" in cmd and "runsc" in cmd
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--memory=256m" in cmd
    assert mock_run.call_args.kwargs["timeout"] == 7


def test_docker_image_missing_falls_back_to_local(monkeypatch):
    """Docker present but image not built -> fall back to local subprocess."""
    import subprocess as real_subprocess

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "docker":
            return real_subprocess.CompletedProcess(
                cmd, 1, stdout="", stderr="Unable to find image 'blastradius-sandbox' locally"
            )
        return real_subprocess.CompletedProcess(cmd, 0, stdout="[VULNERABLE] local\n", stderr="")

    monkeypatch.setattr("blastradius.sandbox.runner.subprocess.run", fake_run)
    runner = SandboxRunner(use_docker=True)
    result = runner.run("print('x')", "print('y')")

    assert result["vulnerable"] is True
    assert calls[-1][0] != "docker"  # last candidate was the local subprocess
    assert any("falling back to local" in w for w in runner.warnings)


def test_docker_success_does_not_fall_back(monkeypatch):
    import subprocess as real_subprocess

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return real_subprocess.CompletedProcess(cmd, 0, stdout="[VULNERABLE] docker\n", stderr="")

    monkeypatch.setattr("blastradius.sandbox.runner.subprocess.run", fake_run)
    runner = SandboxRunner(use_docker=True)
    result = runner.run("print('x')", "print('y')")

    assert result["vulnerable"] is True
    assert all(c[0] == "docker" for c in calls)  # no local fallback used
    assert not any("falling back to local" in w for w in runner.warnings)
