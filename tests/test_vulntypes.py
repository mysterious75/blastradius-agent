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
    _write(tmp_path, "app.py",
        "from flask import request\n"
        "@app.route('/user/<int:id>')\n"
        "def get_user(id):\n"
        "    return get_user_by_id(id)\n",
    )
    assert "idor" in _types(hunter, tmp_path)


def test_idor_not_flagged_with_auth(tmp_path, hunter):
    _write(tmp_path, "app.py",
        "from flask import request\n"
        "@app.route('/user/<int:id>')\n"
        "@login_required\n"
        "def get_user(id):\n"
        "    return get_user_by_id(id)\n",
    )
    assert "idor" not in _types(hunter, tmp_path)


# --- SSTI -------------------------------------------------------------------


def test_ssti_flagged(tmp_path, hunter):
    _write(tmp_path, "app.py",
        "from flask import request, render_template_string\n"
        "def view():\n"
        "    tmpl = request.args.get('tpl')\n"
        "    return render_template_string(tmpl)\n",
    )
    assert "ssti" in _types(hunter, tmp_path)


def test_ssti_template_confirmed_in_sandbox():
    finding = Finding(file="x.py", line=1, vuln_type="ssti", payload="x", confidence=0.9)
    result = run_exploit_sandbox("ssti", reconstruct_target_code(finding))
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


# --- XXE --------------------------------------------------------------------


def test_xxe_flagged_without_defusedxml(tmp_path, hunter):
    _write(tmp_path, "parse.py",
        "import xml.etree.ElementTree as ET\n"
        "def parse_xml(data):\n"
        "    return ET.parse(data)\n",
    )
    assert "xxe" in _types(hunter, tmp_path)


def test_xxe_not_flagged_when_defusedxml_used(tmp_path, hunter):
    _write(tmp_path, "parse.py",
        "from defusedxml import ElementTree as ET\n"
        "def parse_xml(data):\n"
        "    return ET.parse(data)\n",
    )
    assert "xxe" not in _types(hunter, tmp_path)


# --- JWT --------------------------------------------------------------------


def test_jwt_alg_none_flagged(tmp_path, hunter):
    _write(tmp_path, "auth.py",
        "import jwt\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, algorithms=['none'])\n",
    )
    assert "jwt" in _types(hunter, tmp_path)


def test_jwt_verify_disabled_flagged(tmp_path, hunter):
    _write(tmp_path, "auth.py",
        "import jwt\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, verify_signature=False)\n",
    )
    assert "jwt" in _types(hunter, tmp_path)


def test_jwt_secure_decode_not_flagged(tmp_path, hunter):
    _write(tmp_path, "auth.py",
        "import jwt\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, 'secret', algorithms=['HS256'])\n",
    )
    assert "jwt" not in _types(hunter, tmp_path)


def test_jwt_template_confirmed_in_sandbox():
    finding = Finding(file="x.py", line=1, vuln_type="jwt", payload="x", confidence=0.9)
    result = run_exploit_sandbox("jwt", reconstruct_target_code(finding))
    assert result.startswith("CONFIRMED_EXPLOITABLE")
    assert "[VULNERABLE]" in result


# --- GraphQL ----------------------------------------------------------------


def test_graphql_resolver_concat_flagged(tmp_path, hunter):
    _write(tmp_path, "schema.py",
        "class Query(graphene.ObjectType):\n"
        "    def resolve_user(self, info, name):\n"
        "        query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
        "        return db.execute(query)\n",
    )
    assert "graphql" in _types(hunter, tmp_path)


def test_graphql_resolver_parameterized_not_flagged(tmp_path, hunter):
    _write(tmp_path, "schema.py",
        "class Query(graphene.ObjectType):\n"
        "    def resolve_user(self, info, name):\n"
        "        return db.execute('SELECT * FROM users WHERE name = %s', (name,))\n",
    )
    assert "graphql" not in _types(hunter, tmp_path)
