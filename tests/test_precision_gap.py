"""File-level has_source short-circuit fix — assignment-chain is final authority.

Regression tests for the praisonai cross-check gap: a single window.location /
params[ anywhere in a file must NOT taint every sink (e.g. Chrome DevTools
localhost:port fetches in browser.py). Function-parameter args keep the
file-level trust (cross-function taint is unknowable intra-procedurally).
"""

import shutil
import tempfile
from pathlib import Path

from blastradius.hunter.scanner import CVEHunter, _sink_arg_tainted

# browser.py-style: one source line somewhere + a localhost DevTools fetch
BROWSER_STYLE = (
    "class Page:\n"
    "    def get_json(self, port):\n"
    "        req = urllib.request.Request(f'http://localhost:{port}/json')\n"
    "        with urllib.request.urlopen(req) as r:\n"
    "            return r.read()\n"
    "\n"
    "def record_position():\n"
    "    return window.location.search  # one source anywhere in the file\n"
)

# function parameter receiving caller data -> file-level source trust applies
PARAM_STYLE = (
    "import requests\n"
    "\n"
    "def fetch(url):\n"
    "    return requests.get(url).text\n"
    "\n"
    "def handler():\n"
    "    return fetch(request.args.get('target'))\n"
)

# real in-function input still flags
REAL_INPUT = "import os\n\ndef ping():\n    host = request.args.get('host')\n    os.system(host)\n"


def _scan(code: str, suffix: str = ".py"):
    tmp = Path(tempfile.mkdtemp(prefix="br-prec2-"))
    try:
        (tmp / f"app{suffix}").write_text(code, encoding="utf-8")
        return CVEHunter().scan_repo(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _find(fs, vuln_type):
    return next((f for f in fs if f.vuln_type == vuln_type), None)


def test_localhost_devtools_fetch_not_flagged():
    """browser.py-style: localhost:port fetch must NOT be an ssrf candidate even
    though the file has a window.location source elsewhere."""
    fs = _scan(BROWSER_STYLE)
    ssrf = [f for f in fs if f.vuln_type == "ssrf"]
    assert ssrf == [], [f.payload for f in ssrf]


def test_function_parameter_keeps_source_trust():
    """fetch(url) parameter can receive request data from a call site -> flagged."""
    fs = _scan(PARAM_STYLE)
    assert _find(fs, "ssrf") is not None


def test_real_in_function_input_still_flagged():
    assert _find(_scan(REAL_INPUT), "cmd_injection") is not None


def test_sink_arg_tainted_unit():
    lines = BROWSER_STYLE.splitlines()
    # the urlopen line inside get_json: origin is a local f-string -> not tainted
    idx = next(i for i, line in enumerate(lines, 1) if "urlopen(req)" in line)
    assert _sink_arg_tainted(lines[idx - 1], True, lines, idx) is False

    plines = PARAM_STYLE.splitlines()
    idx2 = next(i for i, line in enumerate(plines, 1) if "requests.get(url)" in line)
    # url is a function parameter + file has request.args -> tainted
    assert _sink_arg_tainted(plines[idx2 - 1], True, plines, idx2) is True

    rlines = REAL_INPUT.splitlines()
    idx3 = next(i for i, line in enumerate(rlines, 1) if "os.system(host)" in line)
    assert _sink_arg_tainted(rlines[idx3 - 1], True, rlines, idx3) is True


def test_no_source_file_stays_clean():
    """Without ANY source and with a config origin, the sink stays untarnished."""
    code = (
        "import requests\n"
        "\n"
        "def fetch_status():\n"
        "    url = 'https://api.example.com/health'\n"
        "    return requests.get(url).text\n"
    )
    assert _find(_scan(code), "ssrf") is None
