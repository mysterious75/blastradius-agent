"""Auth-bypass scanner — detection + PoC tests (offline, no mocks)."""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox

VULN_ROLE = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/panel')\n"
    "def panel():\n"
    "    role = request.args.get('role')\n"
    "    if role == 'admin':\n"
    "        return 'admin panel'\n"
    "    return 'denied'\n"
)

SAFE_ROUTE = (
    "from flask import Flask, request\n"
    "from flask_login import login_required, current_user\n"
    "app = Flask(__name__)\n"
    "@app.route('/panel')\n"
    "@login_required\n"
    "def panel():\n"
    "    if not current_user.is_admin:\n"
    "        return 'denied'\n"
    "    return 'admin panel'\n"
)

VULN_HARDCODED = (
    "def login(user, password):\n"
    "    if password == 'admin':\n"
    "        return 'token-abc'\n"
    "    return None\n"
)

VULN_XFF = "def get_client_ip(request):\n    return request.headers['X-Forwarded-For']\n"


def _scan(code: str):
    tmp = Path(tempfile.mkdtemp(prefix="br-auth-"))
    try:
        (tmp / "app.py").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _finding(code: str):
    return next((f for f in _scan(code) if f.vuln_type == "auth_bypass"), None)


def test_detects_client_supplied_role():
    f = _finding(VULN_ROLE)
    assert f is not None
    assert f.cwe == "CWE-287" and f.severity == "HIGH"


def test_safe_route_not_flagged():
    assert _finding(SAFE_ROUTE) is None


def test_detects_hardcoded_credential_compare():
    assert _finding(VULN_HARDCODED) is not None


def test_detects_header_trust():
    assert _finding(VULN_XFF) is not None


def test_poc_confirms_client_role_bypass():
    target = reconstruct_target_code(_finding(VULN_ROLE))
    result = run_exploit_sandbox("auth_bypass", target)
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


def test_poc_rejects_server_side_auth():
    safe = "def target(user_input):\n    return 'denied'  # role from server session\n"
    assert run_exploit_sandbox("auth_bypass", safe).startswith("NOT_EXPLOITABLE")
