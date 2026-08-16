"""Tests for the 5 new vulnerability types (Task 2) — no network/Docker/CAI."""

import pytest

from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox


@pytest.fixture
def hunter():
    return CVEHunter()


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _types(hunter, tmp_path):
    return {f.vuln_type for f in hunter.scan_repo(str(tmp_path))}


# --- IDOR -------------------------------------------------------------------


def test_idor_flagged_without_auth(tmp_path, hunter):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "@app.route('/user/<int:id>')\n"
        "def get_user(id):\n"
        "    return get_user_by_id(id)\n",
    )
    assert "idor" in _types(hunter, tmp_path)


def test_idor_not_flagged_with_auth(tmp_path, hunter):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "@app.route('/user/<int:id>')\n"
        "@login_required\n"
        "def get_user(id):\n"
        "    return get_user_by_id(id)\n",
    )
    assert "idor" not in _types(hunter, tmp_path)


# --- SSTI -------------------------------------------------------------------


def test_ssti_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "app.py",
        "from flask import request, render_template_string\n"
        "def view():\n"
        "    tmpl = request.args.get('tpl')\n"
        "    return render_template_string(tmpl)\n",
    )
    assert "ssti" in _types(hunter, tmp_path)


def test_ssti_template_processed_without_crash():
    finding = Finding(file="x.py", line=1, vuln_type="ssti", payload="x", confidence=0.9)
    code = reconstruct_target_code(finding)
    assert "from_string(user_input).render()" in code
    result = run_exploit_sandbox("ssti", code)
    assert isinstance(result, str)  # processed without crash


# --- XXE --------------------------------------------------------------------


def test_xxe_flagged_without_defusedxml(tmp_path, hunter):
    _write(
        tmp_path,
        "parse.py",
        "import xml.etree.ElementTree as ET\ndef parse_xml(data):\n    return ET.parse(data)\n",
    )
    assert "xxe" in _types(hunter, tmp_path)


def test_xxe_not_flagged_when_defusedxml_used(tmp_path, hunter):
    _write(
        tmp_path,
        "parse.py",
        "from defusedxml import ElementTree as ET\n"
        "def parse_xml(data):\n"
        "    return ET.parse(data)\n",
    )
    assert "xxe" not in _types(hunter, tmp_path)


# --- JWT --------------------------------------------------------------------


def test_jwt_alg_none_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "auth.py",
        "import jwt\ndef decode_token(token):\n    return jwt.decode(token, algorithms=['none'])\n",
    )
    assert "jwt" in _types(hunter, tmp_path)


def test_jwt_verify_disabled_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "auth.py",
        "import jwt\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, verify_signature=False)\n",
    )
    assert "jwt" in _types(hunter, tmp_path)


def test_jwt_secure_decode_not_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "auth.py",
        "import jwt\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, 'secret', algorithms=['HS256'])\n",
    )
    assert "jwt" not in _types(hunter, tmp_path)


def test_jwt_template_processed_without_crash():
    finding = Finding(file="x.py", line=1, vuln_type="jwt", payload="x", confidence=0.9)
    code = reconstruct_target_code(finding)
    assert "jwt.decode(token" in code
    result = run_exploit_sandbox("jwt", code)
    assert isinstance(result, str)  # processed without crash


# --- GraphQL ----------------------------------------------------------------


def test_graphql_resolver_concat_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "schema.py",
        "class Query(graphene.ObjectType):\n"
        "    def resolve_user(self, info, name):\n"
        '        query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "        return db.execute(query)\n",
    )
    assert "graphql" in _types(hunter, tmp_path)


def test_graphql_resolver_parameterized_not_flagged(tmp_path, hunter):
    _write(
        tmp_path,
        "schema.py",
        "class Query(graphene.ObjectType):\n"
        "    def resolve_user(self, info, name):\n"
        "        return db.execute('SELECT * FROM users WHERE name = %s', (name,))\n",
    )
    assert "graphql" not in _types(hunter, tmp_path)


# --- reconstruct_target_code: never crash -------------------------------------


def test_reconstruct_supports_all_vuln_types():
    for vuln_type in ("sqli", "xss", "ssrf", "graphql", "idor", "jwt", "xxe", "ssti"):
        code = reconstruct_target_code(
            Finding(file="x.py", line=1, vuln_type=vuln_type, payload="x", confidence=0.9)
        )
        assert isinstance(code, str) and code.strip()


def test_reconstruct_graphql_template():
    code = reconstruct_target_code(
        Finding(file="s.py", line=1, vuln_type="graphql", payload="x", confidence=0.9)
    )
    assert "# GraphQL resolver" in code and "db.execute" in code
    result = run_exploit_sandbox("graphql", code)
    assert isinstance(result, str)  # processed without crash


def test_reconstruct_idor_and_xxe_templates():
    idor = reconstruct_target_code(
        Finding(file="x.py", line=1, vuln_type="idor", payload="x", confidence=0.9)
    )
    assert 'db.get(request.args.get("id"))' in idor
    xxe = reconstruct_target_code(
        Finding(file="x.py", line=1, vuln_type="xxe", payload="x", confidence=0.9)
    )
    assert "ET.parse(user_input)" in xxe


def test_reconstruct_never_raises_on_unknown_type():
    code = reconstruct_target_code(
        Finding(file="x.py", line=1, vuln_type="rce", payload="x", confidence=0.9)
    )
    assert "process(user_input)" in code


def test_pipeline_handles_graphql_finding_without_crash(tmp_path):
    from blastradius.pipeline import FullPipeline

    (tmp_path / "schema.py").write_text(
        "class Query(graphene.ObjectType):\n"
        "    def resolve_user(self, info, name):\n"
        '        query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "        return db.execute(query)\n",
        encoding="utf-8",
    )
    pipeline = FullPipeline(reports_dir=str(tmp_path / "reports"), db=None)
    result = pipeline.run(str(tmp_path))
    assert any(f.vuln_type == "graphql" for f in result.findings)  # processed, no crash
