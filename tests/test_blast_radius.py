"""Blast radius graph + dependency parser tests — no network, no Neo4j."""

import json


from blastradius.blast_radius.cli import main as cli_main
from blastradius.blast_radius.graph import (
    BlastRadiusGraph,
    MemoryBackend,
    _parse_go_mod,
    _parse_package_json,
    _parse_pipfile,
    _parse_requirements,
    parse_dependencies,
)


# --- Graph ------------------------------------------------------------------


def test_memory_backend_add_and_query():
    g = BlastRadiusGraph(backend="memory")
    g.add_package("lodash", "4.17.20", vulnerable=True)
    g.add_package("lodash", "4.17.21")
    g.add_repo("app-a", "https://github.com/org/app-a")
    g.add_repo("app-b", "https://github.com/org/app-b")
    g.link_package_to_repo("lodash", "app-a")
    g.link_package_to_repo("lodash", "app-b")
    g.link_package_to_repo("requests", "app-a")

    assert g.query_blast_radius("lodash") == ["app-a", "app-b"]
    assert g.query_blast_radius("requests") == ["app-a"]
    assert g.query_blast_radius("unknown") == []
    assert g.backend.packages["lodash"]["version"] == "4.17.21"
    assert g.backend.packages["lodash"]["vulnerable"] is True


def test_link_creates_missing_nodes():
    g = BlastRadiusGraph(backend="memory")
    g.link_package_to_repo("requests", "app-a")
    assert g.query_blast_radius("requests") == ["app-a"]
    assert g.backend.packages["requests"]["version"] == ""


def test_auto_backend_falls_back_to_memory(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7999")
    g = BlastRadiusGraph()  # neo4j driver not installed -> in-memory
    assert isinstance(g.backend, MemoryBackend)
    g.add_package("flask", "2.3.2")
    g.link_package_to_repo("flask", "app")
    assert g.query_blast_radius("flask") == ["app"]


# --- Dependency parsers -----------------------------------------------------


def test_parse_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n"
        "flask==2.3.2\n"
        "requests>=2.31.0\n"
        "numpy\n"
        "-r other.txt\n"
        "psycopg2-binary==2.9.9 ; python_version >= '3.8'\n"
    )
    deps = _parse_requirements(tmp_path / "requirements.txt")
    assert ("flask", "2.3.2") in deps
    assert ("requests", "2.31.0") in deps
    assert ("numpy", "") in deps
    assert ("psycopg2-binary", "2.9.9") in deps
    assert all("other" not in name for name, _ in deps)


def test_parse_package_json(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "app",
                "dependencies": {"lodash": "^4.17.20", "express": "4.18.2"},
                "devDependencies": {"jest": "~29.0.0"},
            }
        )
    )
    deps = _parse_package_json(tmp_path / "package.json")
    assert ("lodash", "4.17.20") in deps
    assert ("express", "4.18.2") in deps
    assert ("jest", "29.0.0") in deps


def test_parse_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\n"
        "go 1.21\n\n"
        "require (\n"
        "\tgithub.com/gorilla/mux v1.8.0\n"
        "\tgolang.org/x/crypto v0.14.0\n"
        ")\n\n"
        "require github.com/google/uuid v1.3.0\n"
    )
    deps = _parse_go_mod(tmp_path / "go.mod")
    assert ("mux", "1.8.0") in deps
    assert ("crypto", "0.14.0") in deps
    assert ("uuid", "1.3.0") in deps


def test_parse_pipfile(tmp_path):
    (tmp_path / "Pipfile").write_text(
        '[[source]]\nurl = "https://pypi.org/simple"\n\n'
        '[packages]\nflask = "==2.3.2"\nrequests = "*"\n\n'
        '[dev-packages]\npytest = "==8.0.0"\n'
    )
    deps = _parse_pipfile(tmp_path / "Pipfile")
    assert ("flask", "2.3.2") in deps
    assert ("requests", "*") in deps
    assert not any(name == "pytest" for name, _ in deps)


def test_parse_dependencies_aggregates_and_dedupes(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nrequests>=2.31.0\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.20"}}))
    (tmp_path / "go.mod").write_text("require github.com/gorilla/mux v1.8.0\n")

    deps = parse_dependencies(str(tmp_path))
    assert deps == [
        ("flask", "2.3.2"),
        ("requests", "2.31.0"),
        ("lodash", "4.17.20"),
        ("mux", "1.8.0"),
    ]


# --- CLI --------------------------------------------------------------------


def test_cli_prints_blast_radius(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nrequests>=2.31.0\n")
    rc = cli_main(["--repo", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    # rich table headers + package rows
    assert "Package" in out and "Affected Repos" in out
    assert "flask" in out and "2.3.2" in out
    assert "requests" in out and "2.31.0" in out


def test_cli_no_dependencies(tmp_path, capsys):
    rc = cli_main(["--repo", str(tmp_path)])
    assert rc == 0
    assert "No dependencies found" in capsys.readouterr().out
