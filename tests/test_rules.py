"""Custom YAML rules, inline suppression, and the learned FP allowlist loop."""

import json

import pytest

from blastradius import rules as rules_mod
from blastradius.hunter.scanner import CVEHunter


@pytest.fixture
def rules_env(tmp_path, monkeypatch):
    """Point BLASTRADIUS_RULES_DIR at a fresh empty rules dir."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    monkeypatch.setenv("BLASTRADIUS_RULES_DIR", str(rules_dir))
    _reset_caches()
    yield rules_dir
    _reset_caches()


def _reset_caches():
    rules_mod._rules_cache.update(sig=None, rules=[])
    rules_mod._lines_cache.clear()
    rules_mod._ignore_cache.update(path=None, mtime=None, entries=[])


def _rule(pattern="super-secret-sink\\(", extra=""):
    return (
        "id: custom-demo\n"
        "name: Custom demo rule\n"
        "description: A dangerous secret sink call.\n"
        "severity: HIGH\n"
        "cwe: CWE-20\n"
        f"pattern: '{pattern}'\n"
        "confidence: 0.9\n" + extra
    )


def _write_rules(rules_dir, name, content):
    (rules_dir / name).write_text(content, encoding="utf-8")


def _scan(repo_path):
    return CVEHunter().scan_repo(str(repo_path))


# --- custom rules -----------------------------------------------------------


def test_custom_rule_matches(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    (tmp_path / "app.py").write_text(
        "def call():\n    super-secret-sink(user_input)\n", encoding="utf-8"
    )
    findings = _scan(tmp_path)
    custom = [f for f in findings if f.vuln_type == "custom"]
    assert len(custom) == 1
    assert custom[0].line == 2
    assert custom[0].severity == "HIGH"
    assert custom[0].cwe == "CWE-20"
    assert "super-secret-sink" in custom[0].payload


def test_match_rules_direct(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    path = tmp_path / "app.py"
    results = rules_mod.match_rules(["super-secret-sink(x)\n", "ok\n"], path)
    assert len(results) == 1
    assert results[0]["vuln_type"] == "custom"
    assert results[0]["line"] == 1
    assert results[0]["file"] == str(path)
    assert set(results[0]) >= {
        "file",
        "line",
        "vuln_type",
        "payload",
        "confidence",
        "severity",
        "cwe",
        "description",
        "remediation",
    }


def test_custom_rule_language_filter(tmp_path, rules_env):
    _write_rules(rules_env, "js_only.yml", _rule(extra="languages: [js]\n"))
    (tmp_path / "app.py").write_text("super-secret-sink(x)\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("super-secret-sink(x)\n", encoding="utf-8")
    custom = [f for f in _scan(tmp_path) if f.vuln_type == "custom"]
    assert len(custom) == 1
    assert custom[0].file.endswith("app.js")


def test_source_required_rule(tmp_path, rules_env):
    _write_rules(rules_env, "src.yml", _rule(extra="source_required: true\n"))
    (tmp_path / "no_source.py").write_text("super-secret-sink(x)\n", encoding="utf-8")
    (tmp_path / "with_source.py").write_text(
        "name = request.args.get('name')\nsuper-secret-sink(name)\n", encoding="utf-8"
    )
    custom = [f for f in _scan(tmp_path) if f.vuln_type == "custom"]
    assert len(custom) == 1
    assert custom[0].file.endswith("with_source.py")


def test_no_rules_dir_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("BLASTRADIUS_RULES_DIR", raising=False)
    _reset_caches()
    (tmp_path / "app.py").write_text("super-secret-sink(x)\n", encoding="utf-8")
    assert not any(f.vuln_type == "custom" for f in _scan(tmp_path))


def test_missing_yaml_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr(rules_mod, "yaml", None)
    _reset_caches()
    (tmp_path / "app.py").write_text("super-secret-sink(x)\n", encoding="utf-8")
    assert not any(f.vuln_type == "custom" for f in _scan(tmp_path))
    assert rules_mod.match_rules(["super-secret-sink(x)\n"], tmp_path / "app.py") == []
    _reset_caches()


# --- inline suppression -----------------------------------------------------


def test_inline_ignore_suppresses_custom_and_builtin(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    (tmp_path / "app.py").write_text(
        "super-secret-sink(x)  # blastradius:ignore\n"
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'  # blastradius:ignore\n',
        encoding="utf-8",
    )
    findings = _scan(tmp_path)
    assert not any(f.vuln_type == "custom" for f in findings)
    assert not any(f.vuln_type == "sqli" for f in findings)


def test_ignore_marker_on_line_above(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    (tmp_path / "app.py").write_text(
        "# blastradius:ignore\nsuper-secret-sink(x)\n", encoding="utf-8"
    )
    assert not any(f.vuln_type == "custom" for f in _scan(tmp_path))


def test_typed_ignore_only_suppresses_that_type(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    (tmp_path / "app.py").write_text(
        "super-secret-sink(x)  # blastradius:ignore custom\n"
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'\n',
        encoding="utf-8",
    )
    findings = _scan(tmp_path)
    assert not any(f.vuln_type == "custom" for f in findings)
    assert any(f.vuln_type == "sqli" for f in findings)


# --- .blastradiusignore -----------------------------------------------------


def test_blastradiusignore_file_suppresses(tmp_path, rules_env):
    _write_rules(rules_env, "demo.yml", _rule())
    (tmp_path / "app.py").write_text(
        "super-secret-sink(a)\nsuper-secret-sink(b)\n", encoding="utf-8"
    )
    (tmp_path / ".blastradiusignore").write_text(
        "# line 2 is a known FP\napp.py:2:custom\n", encoding="utf-8"
    )
    custom = [f for f in _scan(tmp_path) if f.vuln_type == "custom"]
    assert len(custom) == 1
    assert custom[0].line == 1


def test_blastradiusignore_suppresses_builtin(tmp_path, rules_env):
    (tmp_path / "app.py").write_text(
        "name = request.args.get('name')\n"
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'\n',
        encoding="utf-8",
    )
    (tmp_path / ".blastradiusignore").write_text("app.py:2:sqli\n", encoding="utf-8")
    assert not any(f.vuln_type == "sqli" for f in _scan(tmp_path))


# --- FP feedback loop -------------------------------------------------------


def test_add_to_allowlist_skips_learned_pattern(tmp_path, monkeypatch, rules_env):
    monkeypatch.setenv("BLASTRADIUS_HOME", str(tmp_path))
    rules_mod.add_to_allowlist("custom", r"super-secret-sink\(")
    learned = json.loads(
        (tmp_path / ".blastradius" / "learned_rules.json").read_text(encoding="utf-8")
    )
    # pattern persisted in both the per-type list and the flat skip_patterns
    assert r"super-secret-sink\(" in learned["line_skip_patterns"]["custom"]
    assert r"super-secret-sink\(" in learned["skip_patterns"]

    _write_rules(rules_env, "demo.yml", _rule())
    _write_rules(rules_env, "other.yml", _rule(pattern="other-sink\\("))
    (tmp_path / "app.py").write_text("super-secret-sink(x)\nother-sink(y)\n", encoding="utf-8")
    custom = [f for f in _scan(tmp_path) if f.vuln_type == "custom"]
    # the learned line is skipped; an unrelated rule still fires
    assert len(custom) == 1
    assert "other-sink" in custom[0].payload


def test_add_to_allowlist_merges_existing_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_HOME", str(tmp_path))
    rules_mod.add_to_allowlist("custom", r"one-sink\(")
    rules_mod.add_to_allowlist("sqli", r"two-sink\(")
    learned = json.loads(
        (tmp_path / ".blastradius" / "learned_rules.json").read_text(encoding="utf-8")
    )
    assert learned["line_skip_patterns"]["custom"] == [r"one-sink\("]
    assert learned["line_skip_patterns"]["sqli"] == [r"two-sink\("]
