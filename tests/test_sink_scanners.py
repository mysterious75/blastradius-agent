"""New sink scanners (cmd_injection, traversal, crlf) — detection + PoC tests.

All offline, no mocks: detection runs the real CVEHunter over temp files, and
the PoCs run in the real sandbox (local subprocess path).
"""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox

VULN_CMD = (
    "from flask import Flask, request\n"
    "import os\n"
    "app = Flask(__name__)\n"
    "@app.route('/ping')\n"
    "def ping():\n"
    "    host = request.args.get('host')\n"
    "    cmd = 'ping -c 1 ' + host\n"
    "    os.system(cmd)\n"
)

SAFE_CMD = (
    "import subprocess\n"
    "import shlex\n"
    "def ping(host):\n"
    "    return subprocess.run(['ping', '-c', '1', shlex.quote(host)])\n"
)

VULN_TRAVERSAL = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/read')\n"
    "def read():\n"
    "    path = request.args.get('path')\n"
    "    return open(path).read()\n"
)

SAFE_TRAVERSAL = (
    "import os\n"
    "def read(path):\n"
    "    base = os.path.abspath('/srv')\n"
    "    full = os.path.abspath(os.path.join(base, path))\n"
    "    if not full.startswith(base):\n"
    "        return 'blocked'\n"
    "    return open(full).read()\n"
)

VULN_CRLF = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/go')\n"
    "def go():\n"
    "    nxt = request.args.get('next')\n"
    "    resp = app.make_response('', 302)\n"
    "    resp.headers.set('Location', '/go/' + nxt)\n"
    "    return resp\n"
)


def _scan(code: str):
    tmp = Path(tempfile.mkdtemp(prefix="br-sink-"))
    try:
        (tmp / "app.py").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _finding(code: str, vuln_type: str):
    return next((f for f in _scan(code) if f.vuln_type == vuln_type), None)


# --- Command injection -------------------------------------------------------


def test_detects_cmd_injection():
    f = _finding(VULN_CMD, "cmd_injection")
    assert f is not None
    assert f.cwe == "CWE-78" and f.severity == "CRITICAL"


def test_cmd_injection_safe_not_flagged():
    assert _finding(SAFE_CMD, "cmd_injection") is None


def test_cmd_injection_poc_confirms():
    target = reconstruct_target_code(_finding(VULN_CMD, "cmd_injection"))
    assert run_exploit_sandbox("cmd_injection", target).startswith("CONFIRMED_EXPLOITABLE")


def test_cmd_injection_poc_rejects_safe():
    assert run_exploit_sandbox("cmd_injection", SAFE_CMD).startswith("NOT_EXPLOITABLE")


# --- Path traversal ----------------------------------------------------------


def test_detects_traversal():
    f = _finding(VULN_TRAVERSAL, "traversal")
    assert f is not None
    assert f.cwe == "CWE-22"


def test_traversal_safe_not_flagged():
    assert _finding(SAFE_TRAVERSAL, "traversal") is None


def test_traversal_poc_confirms():
    target = reconstruct_target_code(_finding(VULN_TRAVERSAL, "traversal"))
    result = run_exploit_sandbox("traversal", target)
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


def test_traversal_poc_rejects_safe():
    assert run_exploit_sandbox("traversal", SAFE_TRAVERSAL).startswith("NOT_EXPLOITABLE")


# --- CRLF --------------------------------------------------------------------


def test_detects_crlf():
    f = _finding(VULN_CRLF, "crlf")
    assert f is not None
    assert f.cwe == "CWE-93"


def test_crlf_poc_confirms():
    target = reconstruct_target_code(_finding(VULN_CRLF, "crlf"))
    result = run_exploit_sandbox("crlf", target)
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result
