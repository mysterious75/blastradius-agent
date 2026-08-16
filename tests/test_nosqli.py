"""NoSQL injection (nosqli, CWE-943) — detection tests (offline, no mocks).

Candidate-only: no sandbox PoC template exists, so detection is tested end to
end through both the CVEHunter pipeline and the self-contained package
scanner. Safe markers (sanitize/validate/parameterized/ObjectId) suppress.
"""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.scanners import get_scanner

VULN_PYMONGO = (
    "from flask import Flask, request\n"
    "from pymongo import MongoClient\n"
    "app = Flask(__name__)\n"
    "db = MongoClient().test\n"
    "@app.route('/login')\n"
    "def login():\n"
    "    user = db.users.find_one({'username': request.args.get('username')})\n"
    "    return 'ok' if user else 'denied'\n"
)

VULN_MONGOOSE = (
    "const express = require('express');\n"
    "const app = express();\n"
    "app.post('/login', (req, res) => {\n"
    "    const user = db.users.findOne({ username: req.body.username });\n"
    "    res.send(user ? 'ok' : 'denied');\n"
    "});\n"
)

SAFE_SANITIZE = (
    "from flask import Flask, request\n"
    "from pymongo import MongoClient\n"
    "app = Flask(__name__)\n"
    "db = MongoClient().test\n"
    "@app.route('/login')\n"
    "def login():\n"
    "    user = db.users.find_one({'username': sanitize(request.json.get('username'))})\n"
    "    return 'ok' if user else 'denied'\n"
)

SAFE_VALIDATE = (
    "from flask import Flask, request\n"
    "from pymongo import MongoClient\n"
    "app = Flask(__name__)\n"
    "db = MongoClient().test\n"
    "@app.route('/login')\n"
    "def login():\n"
    "    user = db.users.find_one({'username': validate(request.json.get('username'))})\n"
    "    return 'ok' if user else 'denied'\n"
)

SAFE_PARAMETERIZED = (
    "from pymongo import MongoClient\n"
    "db = MongoClient().test\n"
    "def login(username):\n"
    "    q = build_parameterized_query(username)\n"
    "    return db.users.find_one(q)\n"
)


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-nosqli-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _nosqli_finding(code: str, suffix: str = ".py"):
    return next((f for f in _scan(code, suffix) if f.vuln_type == "nosqli"), None)


# --- Hunter pipeline ----------------------------------------------------------


def test_hunter_detects_pymongo_find_one_with_request_input():
    f = _nosqli_finding(VULN_PYMONGO)
    assert f is not None
    assert f.cwe == "CWE-943"
    assert f.severity == "HIGH"
    assert f.confidence >= 0.85  # file-level source present


def test_hunter_detects_mongoose_findone():
    f = _nosqli_finding(VULN_MONGOOSE, suffix=".js")
    assert f is not None
    assert f.cwe == "CWE-943"


def test_hunter_skips_sanitized_and_validated():
    assert _scan(SAFE_SANITIZE) == []
    assert _scan(SAFE_VALIDATE) == []


def test_hunter_skips_parameterized():
    assert _scan(SAFE_PARAMETERIZED) == []


# --- Self-contained package scanner -------------------------------------------


def test_package_scanner_detects_find_one():
    scanner = get_scanner("nosqli")
    findings = scanner.detect(VULN_PYMONGO)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type == "nosqli"
    assert finding.cwe == "CWE-943"
    assert finding.severity == "HIGH"
    assert finding.confidence >= 0.85


def test_package_scanner_skips_safe():
    scanner = get_scanner("nosqli")
    assert scanner.detect(SAFE_SANITIZE) == []
    assert scanner.detect(SAFE_VALIDATE) == []
    assert scanner.detect(SAFE_PARAMETERIZED) == []


# --- reconstruct_target_code (candidate-only: no PoC template) ----------------


def test_reconstruct_nosqli_target():
    code = reconstruct_target_code(
        Finding(file="x.py", line=1, vuln_type="nosqli", payload="x", confidence=0.9)
    )
    assert "def target(user_input):" in code
    assert "q = {'username': user_input}" in code
    assert "return 'matched' if q['username'] else 'denied'" in code
