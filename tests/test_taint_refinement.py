"""Constant-sink taint refinement — off, offline, no mocks.

A sink whose argument does NOT reference user-controlled data (os.system("cls"),
requests.get("https://static..."), os.system(api_url) where api_url is a plain
constant) must NOT produce a candidate finding in a file with no user-input
source. The same sink fed from request data still fires.
"""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, _sink_arg_tainted

CONSTANT_CMD = 'import os\ndef clear():\n    os.system("cls" if os.name == "nt" else "clear")\n'

CONSTANT_SSRF = (
    "import requests\ndef fetch():\n    return requests.get('https://static.example/data.json')\n"
)

TAINTED_CMD = (
    "from flask import Flask, request\n"
    "import os\n"
    "app = Flask(__name__)\n"
    "@app.route('/ping')\n"
    "def ping():\n"
    "    host = request.args.get('host')\n"
    "    os.system(host)\n"
)

CONSTANT_ENV_CMD = (
    "import os\n"
    "def ping():\n"
    '    api_url = "https://api.example.com/health"\n'
    "    os.system(api_url)\n"
)

SOURCE_ELSEWHERE_CMD = (
    "import os\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/ping')\n"
    "def ping():\n"
    '    api_url = "https://api.example.com/health"\n'
    "    os.system(api_url)\n"
    "    return request.args.get('x')\n"
)


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-taint-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- constant sinks are dropped, tainted sinks still fire --------------------


def test_constant_sink_not_flagged():
    findings = _scan(CONSTANT_CMD)
    assert not any(f.vuln_type == "cmd_injection" for f in findings)
    findings = _scan(CONSTANT_SSRF)
    assert not any(f.vuln_type == "ssrf" for f in findings)


def test_tainted_sink_flagged():
    f = next((f for f in _scan(TAINTED_CMD) if f.vuln_type == "cmd_injection"), None)
    assert f is not None
    assert f.cwe == "CWE-78"
    assert f.confidence >= 0.9  # file-level source present


def test_env_var_sink_downgraded():
    # plain string constant, no source anywhere -> no finding
    assert _scan(CONSTANT_ENV_CMD) == []
    # same sink line in a file with request.args elsewhere -> finding
    # (has_source=True path keeps the finding above threshold)
    f = next((f for f in _scan(SOURCE_ELSEWHERE_CMD) if f.vuln_type == "cmd_injection"), None)
    assert f is not None


# --- _sink_arg_tainted unit checks -------------------------------------------


def test_sink_arg_tainted_constants():
    assert _sink_arg_tainted("os.system('cls')", False) is False
    assert _sink_arg_tainted("os.system(api_url)", False) is False
    assert _sink_arg_tainted('os.system("cls" if os.name == "nt" else "clear")', False) is False
    assert _sink_arg_tainted("requests.get('https://static.example/data.json')", False) is False
    assert _sink_arg_tainted("requests.get(hs6_url)", False) is False


def test_sink_arg_tainted_identifiers():
    assert _sink_arg_tainted("os.system(host)", False) is True
    assert _sink_arg_tainted("requests.get(url)", False) is True
    assert _sink_arg_tainted("pickle.loads(data)", False) is True
    assert _sink_arg_tainted('open(file_path + name, "r")', False) is True


def test_sink_arg_tainted_file_source_short_circuit():
    # any file-level source marks every sink line tainted (conservative)
    assert _sink_arg_tainted("os.system('cls')", True) is True
    assert _sink_arg_tainted("requests.get('https://static.example/data.json')", True) is True
