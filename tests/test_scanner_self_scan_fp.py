"""CI-scanner false positives: code samples inside strings, comments, docstrings.

The diff gate runs ``blastradius.scanners`` (not the hunter). Those scanners
must not flag a *quoted* vulnerable snippet (test fixture / PoC template) or a
comment, and language-specific scanners must stay on their own language. This
regression suite was added after the project's own PR scan flagged its scanner
source and tests.
"""

import pytest

from blastradius.scanners import scan_file
from blastradius.scanners._util import (
    assigned_from_source,
    code_only,
    first_arg_var,
    scan_lines,
    strip_literals,
)

pytestmark = [pytest.mark.unit, pytest.mark.integration]


def test_strip_literals_handles_nested_quotes():
    assert "open" not in strip_literals("SAMPLE = 'open(name, \"r\")'")


def test_code_only_masks_comments_and_literals():
    assert "innerHTML" not in code_only("value = 1  # innerHTML")
    assert "innerHTML" in code_only("el.innerHTML = payload")


def test_first_arg_var_and_assignment_chain():
    assert first_arg_var("return open(path).read()") == "path"
    code = "from flask import request\npath = request.args.get('p')\n"
    assert assigned_from_source(code, "path")
    assert not assigned_from_source(code, "tmp")


def test_scan_lines_skips_comments_and_docstrings():
    seen = []

    def predicate(line, idx):
        seen.append(idx)
        return None

    code = '"""doc\ninnerHTML\n"""\n# innerHTML\nvalue = 1\n'
    scan_lines(code, None, predicate)
    assert seen == [5]


def _scan(tmp_path, name, code):
    path = tmp_path / name
    path.write_text(code, encoding="utf-8")
    return scan_file(str(path))


def test_quoted_vulnerable_snippets_are_not_findings(tmp_path):
    code = (
        "FIXTURES = {\n"
        "    \"xss\": 'el.innerHTML = payload;',\n"
        '    "sql": "SELECT * FROM users WHERE name = \'" + name + "\'",\n'
        "}\n"
    )
    assert _scan(tmp_path, "fixtures.py", code) == []


def test_nested_quotes_in_quoted_snippet_do_not_leak(tmp_path):
    code = "SAMPLE = 'open(name, \"r\")'\n"
    assert _scan(tmp_path, "sample.py", code) == []


def test_comments_and_docstrings_are_not_findings(tmp_path):
    code = (
        '"""\n'
        "Example: el.innerHTML = payload;\n"
        "Example: os.system(user_input)\n"
        '"""\n'
        "# el.innerHTML = payload;\n"
        "// var x = document.write(y);\n"
        "def safe():\n"
        "    return 1\n"
    )
    assert _scan(tmp_path, "comments.py", code) == []


def test_solidity_rules_do_not_run_on_python(tmp_path):
    code = "tx.origin == msg.sender\na = b / c * d\n"
    findings = _scan(tmp_path, "not_contract.py", code)
    assert all(f.vuln_type != "solidity" for f in findings)


def test_traversal_ignores_local_temp_paths(tmp_path):
    code = (
        "import shutil\n"
        "import tempfile\n"
        "from pathlib import Path\n"
        "def f():\n"
        '    tmp = Path(tempfile.mkdtemp(prefix="br-"))\n'
        "    shutil.rmtree(tmp, ignore_errors=True)\n"
    )
    assert _scan(tmp_path, "local.py", code) == []


def test_traversal_still_detects_source_assigned_path(tmp_path):
    code = (
        "from flask import request\n"
        "def read():\n"
        "    path = request.args.get('path')\n"
        "    return open(path).read()\n"
    )
    findings = _scan(tmp_path, "app.py", code)
    assert any(f.vuln_type == "traversal" for f in findings)
