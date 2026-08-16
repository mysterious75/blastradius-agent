"""IDOR scanner upgrade — multi-language detection + PoC tests (offline)."""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox

VULN_PY = (
    "from flask import Flask, request, jsonify\n"
    "app = Flask(__name__)\n"
    "USERS = {'1': {'name': 'alice'}, '2': {'name': 'bob'}}\n"
    "@app.route('/user/<int:user_id>')\n"
    "def user(user_id):\n"
    "    return jsonify(USERS.get(str(user_id)))\n"
)

SAFE_PY = (
    "from flask import Flask, request\n"
    "from flask_login import login_required, current_user\n"
    "app = Flask(__name__)\n"
    "@app.route('/user/<int:user_id>')\n"
    "@login_required\n"
    "def user(user_id):\n"
    "    if current_user.id != user_id:\n"
    "        return 'denied'\n"
    "    return get_profile(user_id)\n"
)

VULN_PHP = (
    "<?php\n"
    "function getUser() {\n"
    "    $id = $_GET['user_id'];\n"
    '    $row = db_query("SELECT * FROM users WHERE id = $id");\n'
    "    echo json_encode($row);\n"
    "}\n"
)

VULN_JS = (
    "const express = require('express');\n"
    "const app = express();\n"
    "app.get('/user/:id', (req, res) => {\n"
    "  const uid = req.params.id;\n"
    "  res.json(users[uid]);\n"
    "});\n"
)

VULN_RB = "def show\n  @user = User.find(params[:id])\n  render json: @user\nend\n"

VULN_GO = (
    "func GetUser(w http.ResponseWriter, r *http.Request) {\n"
    '    id := r.URL.Query().Get("user_id")\n'
    "    u := store.Get(id)\n"
    "    json.NewEncoder(w).Encode(u)\n"
    "}\n"
)

SAFE_JAVA = (
    '@GetMapping("/user/{id}")\n'
    "public User getUser(@PathVariable Long id) {\n"
    "    checkPermission(currentUser(), id);\n"
    "    return service.findById(id);\n"
    "}\n"
)


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-idor-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _finding(code: str, suffix: str = ".py"):
    return next((f for f in _scan(code, suffix) if f.vuln_type == "idor"), None)


def test_detects_python_idor():
    f = _finding(VULN_PY)
    assert f is not None
    assert f.cwe == "CWE-639" and f.severity == "HIGH"


def test_python_ownership_check_not_flagged():
    assert _finding(SAFE_PY) is None


def test_detects_php_idor():
    assert _finding(VULN_PHP, suffix=".php") is not None


def test_detects_javascript_idor():
    assert _finding(VULN_JS, suffix=".js") is not None


def test_detects_ruby_idor():
    assert _finding(VULN_RB, suffix=".rb") is not None


def test_detects_go_idor():
    assert _finding(VULN_GO, suffix=".go") is not None


def test_java_with_permission_check_not_flagged():
    assert _finding(SAFE_JAVA, suffix=".java") is None


def test_idor_poc_confirms_cross_user_read():
    target = reconstruct_target_code(_finding(VULN_PY))
    result = run_exploit_sandbox("idor", target)
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


def test_idor_poc_rejects_ownership_check():
    safe = "def target(user_input):\n    return 'denied' if user_input != '1' else 'own-data'\n"
    assert run_exploit_sandbox("idor", safe).startswith("NOT_EXPLOITABLE")
