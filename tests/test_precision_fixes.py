"""Precision fixes — assignment-chain taint, sandboxed-exec downgrade,
CRLF taint context, and test-fixture skipping. Offline, no mocks.

These pin the four precision regressions found cross-checking a real repo
(praisonai): client-library calls were flagged as tainted purely because of
variable NAMES (req, data, url), ``urllib.request.Request(`` was read as a
source, sandboxed ``exec(compiled_code, safe_globals)`` was reported as code
injection, config-backed Authorization headers were flagged as CRLF injection,
and self-test fixtures under ``.github/scripts`` leaked fake secrets.
"""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, _sink_arg_tainted
from blastradius.taint import is_var_tainted


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-precision-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- FIX 1: assignment-chain taint, not name-based --------------------------


def test_client_lib_urlopen_not_tainted():
    lines = [
        "def f():",
        "    req = urllib.request.Request(url)",
        "    with urllib.request.urlopen(req) as r:",
        "        return r.read()",
    ]
    assert is_var_tainted(lines, 2, "req") is False
    assert _sink_arg_tainted(lines[2], False, lines, 3) is False


def test_real_input_tainted():
    lines = ["def f():", "    x = request.args.get('q')", "    os.system(x)"]
    assert is_var_tainted(lines, 2, "x") is True
    assert _sink_arg_tainted(lines[2], False, lines, 3) is True


def test_config_origin_not_tainted():
    lines = [
        "def f():",
        "    full_url = f'{self.base_url}/api'",
        "    requests.get(full_url)",
    ]
    assert is_var_tainted(lines, 2, "full_url") is False
    assert _sink_arg_tainted(lines[2], False, lines, 3) is False
    # end-to-end: config-constant sink produces no candidate finding
    code = (
        "class Client:\n"
        "    base_url = 'https://api.example.com'\n"
        "    def fetch(self):\n"
        "        full_url = f'{self.base_url}/api'\n"
        "        return requests.get(full_url)\n"
    )
    assert not any(f.vuln_type == "ssrf" for f in _scan(code))


def test_urllib_request_module_path_not_a_source():
    # `request` inside a module path must not be treated as a source
    lines = [
        "def f():",
        "    req = urllib.request.Request(url)",
        "    return urllib.request.urlopen(req).read()",
    ]
    assert is_var_tainted(lines, 1, "req") is False


# --- FIX 2: sandboxed exec is not code injection ----------------------------


def test_sandboxed_exec_downgraded():
    sandboxed = (
        "import ast\n"
        "def run(code):\n"
        "    tree = ast.parse(code)\n"
        "    validate_node(tree)\n"
        "    compiled_code = compile(tree, '<sandbox>', 'exec')\n"
        "    exec(compiled_code, safe_globals)\n"
    )
    findings = _scan(sandboxed)
    assert not any(f.vuln_type == "cmd_injection" for f in findings)

    # plain exec(user_input) is still a finding
    plain = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/exec')\n"
        "def run():\n"
        "    code = request.args.get('code')\n"
        "    exec(code)\n"
    )
    findings = _scan(plain)
    assert any(f.vuln_type == "cmd_injection" for f in findings)


# --- FIX 3: CRLF requires a tainted header value ----------------------------


def test_crlf_requires_tainted_value():
    # Authorization header built from config/env token -> NOT flagged
    config_headers = (
        "import os\n"
        "def send():\n"
        "    token = os.getenv('API_TOKEN')\n"
        "    headers['Authorization'] = f'Bearer {token}'\n"
        "    return headers\n"
    )
    findings = _scan(config_headers)
    assert not any(f.vuln_type == "crlf" for f in findings)

    # request-derived value flowing into a header -> flagged
    tainted_header = (
        "def redirect():\n"
        "    loc = '/go/' + request.args.get('next')\n"
        "    headers['Location'] = loc\n"
        "    return headers\n"
    )
    findings = _scan(tainted_header)
    assert any(f.vuln_type == "crlf" for f in findings)


def test_crlf_literal_build_still_flagged():
    # a sink line that literally embeds CR/LF escapes next to a variable stays
    # flagged even without a traced user-input origin
    code = (
        "def send():\n    body = build_body()\n    return sendmail(to, subject, body + '\\r\\n')\n"
    )
    findings = _scan(code)
    assert any(f.vuln_type == "crlf" for f in findings)


# --- FIX 4: .github/scripts self-test fixtures are skipped ------------------


def test_fixture_skip():
    tmp = Path(tempfile.mkdtemp(prefix="br-fixture-"))
    try:
        fixture = tmp / ".github" / "scripts"
        fixture.mkdir(parents=True)
        (fixture / "selftest.js").write_text(
            'const fake = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";\n',
            encoding="utf-8",
        )
        (tmp / "src").mkdir()
        (tmp / "src" / "keys.js").write_text(
            'const real = "ghp_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210";\n',
            encoding="utf-8",
        )
        findings = CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    assert not any("selftest.js" in f.file for f in findings)
    assert any(f.vuln_type == "secret" and "keys.js" in f.file for f in findings)
