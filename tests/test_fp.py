"""False-positive reduction tests (Task 1) — no network, no Docker, no CAI."""

import pytest

from blastradius.hunter.scanner import CVEHunter


@pytest.fixture
def hunter():
    return CVEHunter()


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_fstring_sql_is_not_flagged(tmp_path, hunter):
    _write(tmp_path, "app.py",
        "from flask import request\n"
        "def f():\n"
        "    uid = request.args.get('uid')\n"
        "    query = f\"SELECT * FROM users WHERE id={uid}\"\n"
        "    return db.execute(query)\n",
    )
    findings = hunter.scan_repo(str(tmp_path))
    assert not any(f.vuln_type == "sqli" for f in findings)


def test_print_in_docstring_and_comment_is_not_xss(tmp_path, hunter):
    _write(tmp_path, "mod.py",
        '"""\n'
        "Usage example:\n"
        "    print('hello world')\n"
        '"""\n'
        "# print('also a comment')\n"
        "def f():\n"
        "    pass\n",
    )
    findings = hunter.scan_repo(str(tmp_path))
    assert not any(f.vuln_type == "xss" for f in findings)


def test_minified_vendor_and_dist_files_are_skipped(tmp_path, hunter):
    _write(tmp_path, "static/js/app.min.js",
        "document.write('<img src=x onerror=alert(1)>');\n"
    )
    _write(tmp_path, "vendor/lib.js",
        "el.innerHTML = payload;\n"
    )
    _write(tmp_path, "dist/bundle.js",
        "document.getElementById('x').innerHTML = data;\n"
    )
    # a normal first-party file must still be scanned
    _write(tmp_path, "app.js",
        "const el = document.getElementById('out');\n"
        "el.innerHTML = userInput;\n"
    )
    findings = hunter.scan_repo(str(tmp_path))
    xss = [f for f in findings if f.vuln_type == "xss"]
    assert len(xss) == 1
    assert xss[0].file.endswith("app.js")


def test_migrations_directory_is_skipped(tmp_path, hunter):
    _write(tmp_path, "migrations/0001_init.py",
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
    )
    _write(tmp_path, "app.py",
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
    )
    findings = hunter.scan_repo(str(tmp_path))
    sqli = [f for f in findings if f.vuln_type == "sqli"]
    assert len(sqli) == 1
    from pathlib import Path

    assert "migrations" not in Path(sqli[0].file).parts
    assert sqli[0].file.endswith("app.py")


def test_sql_literal_without_variable_is_not_flagged(tmp_path, hunter):
    _write(tmp_path, "app.py",
        "query = \"SELECT * FROM users\"\n"
        "db.execute(\"SELECT 1\")\n"
        "document.write(\"static text\")\n"
    )
    findings = hunter.scan_repo(str(tmp_path))
    assert not any(f.vuln_type == "sqli" for f in findings)
    assert not any(f.vuln_type == "xss" for f in findings)
