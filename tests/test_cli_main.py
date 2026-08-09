"""Unified CLI + version tests — subcommands dispatched via mocks, no network."""

import pytest

from blastradius.cli.main import main
from blastradius.version import __author__, __license__, __version__


def test_version_module():
    assert __version__ == "1.0.0"
    assert __author__ == "BlastRadius Team"
    assert __license__ == "MIT"


def test_version_command(capsys):
    rc = main(["version"])
    assert rc == 0
    assert "BlastRadius Agent v1.0.0" in capsys.readouterr().out


def test_banner_uses_version():
    from blastradius.cli.display import VERSION

    assert VERSION == __version__


def test_dispatch_scan(monkeypatch):
    captured = {}

    def fake(args):
        captured["target"] = args.target
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_scan", fake)
    assert main(["scan", "--target", "https://github.com/org/repo"]) == 0
    assert captured["target"] == "https://github.com/org/repo"


def test_dispatch_hunt(monkeypatch):
    captured = {}

    def fake(args):
        captured["strategy"] = args.strategy
        captured["max"] = args.max
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_hunt", fake)
    assert main(["hunt", "--strategy", "pypi", "--max", "10"]) == 0
    assert captured == {"strategy": "pypi", "max": 10}


def test_dispatch_blast(monkeypatch):
    captured = {}

    def fake(args):
        captured["repo"] = args.repo
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_blast", fake)
    assert main(["blast", "--repo", "./path"]) == 0
    assert captured["repo"] == "./path"


def test_dispatch_providers(monkeypatch):
    captured = {}

    def fake(args):
        captured["action"] = args.action
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_providers", fake)
    assert main(["providers", "test"]) == 0
    assert captured["action"] == "test"


def test_dispatch_cve(monkeypatch):
    captured = {}

    def fake(args):
        captured["action"] = args.action
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_cve", fake)
    assert main(["cve", "list"]) == 0
    assert captured["action"] == "list"


def test_dispatch_export(monkeypatch):
    captured = {}

    def fake(args):
        captured["format"] = args.format
        captured["output"] = args.output
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_export", fake)
    assert main(["export", "--format", "html", "--output", "r.html"]) == 0
    assert captured == {"format": "html", "output": "r.html"}


def test_dispatch_setup(monkeypatch):
    called = []

    def fake(_args):
        called.append(True)
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_setup", fake)
    assert main(["setup"]) == 0
    assert called == [True]


def test_dispatch_dashboard(monkeypatch):
    called = []

    def fake(_args):
        called.append(True)
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_dashboard", fake)
    assert main(["dashboard"]) == 0
    assert called == [True]


def test_api_subcommand_flags(monkeypatch):
    captured = {}

    def fake(args):
        captured["port"] = args.port
        captured["reload"] = args.reload
        return 0

    monkeypatch.setattr("blastradius.cli.main.cmd_api", fake)
    assert main(["api", "--port", "9000", "--reload"]) == 0
    assert captured == {"port": 9000, "reload": True}


def test_requires_subcommand():
    with pytest.raises(SystemExit):
        main([])
