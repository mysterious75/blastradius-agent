"""REAL-repo PoC tests — findings proven against the actual repo file.

No network and no Docker daemon required: the runner falls back to the
unsandboxed local subprocess (trusted template PoCs driving the repo's own
code), matching the rest of the offline suite.
"""

from blastradius.hunter.scanner import Finding, real_target_code
from blastradius.sandbox.real_repo import run_real_poc

TRAVERSAL_APP = "import os\n\ndef target(user_input):\n    return open(user_input).read()\n"

SAFE_TRAVERSAL_APP = (
    "def target(user_input):\n"
    '    if "/" in user_input or "\\\\" in user_input:\n'
    '        return "blocked"\n'
    "    return open(user_input).read()\n"
)

NO_FUNCTION_APP = "import os\nUSER_LOOKUP = 'SELECT * FROM users'\nprint('booted')\n"


def _finding(path, line, vuln_type="traversal"):
    return Finding(
        file=str(path),
        line=line,
        vuln_type=vuln_type,
        payload="open(user_input).read()",
        confidence=0.9,
    )


def test_real_target_code_extracts_function(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(TRAVERSAL_APP, encoding="utf-8")
    snippet = real_target_code(_finding(app, 4), str(tmp_path))
    assert "def target" in snippet
    assert "TARGET" in snippet
    assert snippet.startswith("import os")


def test_real_poc_confirms(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(TRAVERSAL_APP, encoding="utf-8")
    result = run_real_poc(_finding(app, 4), str(tmp_path))
    assert result["vulnerable"] is True
    assert result["real_file"] is True


def test_real_poc_safe_code_rejected(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(SAFE_TRAVERSAL_APP, encoding="utf-8")
    result = run_real_poc(_finding(app, 4), str(tmp_path))
    assert result["vulnerable"] is False


def test_missing_function_returns_empty(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(NO_FUNCTION_APP, encoding="utf-8")
    finding = _finding(app, 2)
    assert real_target_code(finding, str(tmp_path)) == ""
    result = run_real_poc(finding, str(tmp_path))
    assert result == {"vulnerable": False, "error": "no real target function"}
