"""Plugin system tests — builtins discovered, events fired, no network."""

import csv
import os


from blastradius.hunter.scanner import Finding
from blastradius.plugins.base import BasePlugin
from blastradius.plugins.builtin.csv_export_plugin import CsvExportPlugin
from blastradius.plugins.loader import PluginLoader
from blastradius.plugins.__main__ import main as plugins_main


def make_finding(vuln_type="sqli"):
    return Finding(
        file="/repo/app.py",
        line=5,
        vuln_type=vuln_type,
        payload="SELECT * FROM users",
        confidence=0.9,
        severity="HIGH",
        cwe="CWE-89",
        description="d",
        remediation="r",
    )


def test_base_plugin_defaults():
    p = BasePlugin()
    assert p.name == "base"
    p.on_finding(make_finding())  # must not raise
    p.on_patch(None)
    p.on_scan_complete(None)
    assert p.register_scanner() == {}
    assert callable(p.register_tool())


def test_loader_discovers_builtins():
    loader = PluginLoader()
    names = {p.name for p in loader.plugins}
    assert {"jira", "linear", "csv_export"} <= names


def test_loader_discovers_custom_plugin(tmp_path):
    (tmp_path / "recorder_plugin.py").write_text(
        "from blastradius.plugins.base import BasePlugin\n"
        "class RecorderPlugin(BasePlugin):\n"
        "    name = 'recorder'\n"
        "    def __init__(self):\n"
        "        self.events = []\n"
        "    def on_finding(self, finding):\n"
        "        self.events.append(('finding', finding.vuln_type))\n"
        "    def on_patch(self, patch):\n"
        "        self.events.append(('patch', True))\n"
        "    def on_scan_complete(self, results):\n"
        "        self.events.append(('complete', True))\n",
        encoding="utf-8",
    )
    loader = PluginLoader(extra_dirs=[tmp_path])
    recorder = next(p for p in loader.plugins if p.name == "recorder")

    loader.on_finding(make_finding())
    loader.on_patch(None)
    loader.on_scan_complete(None)

    assert recorder.events == [("finding", "sqli"), ("patch", True), ("complete", True)]


def test_csv_export_writes_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CSV_EXPORT_DIR", str(tmp_path))
    plugin = CsvExportPlugin()
    plugin.on_finding(make_finding())
    plugin.on_finding(make_finding(vuln_type="xss"))
    plugin.on_scan_complete(None)

    out = tmp_path / "findings.csv"
    assert out.exists()
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["file", "line", "vuln_type", "severity", "confidence", "payload"]
    assert rows[1][2] == "sqli" and rows[2][2] == "xss"


def test_csv_export_skips_when_no_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("CSV_EXPORT_DIR", str(tmp_path))
    CsvExportPlugin().on_scan_complete(None)
    assert not (tmp_path / "findings.csv").exists()


def test_jira_plugin_graceful_without_env():
    from blastradius.plugins.builtin import jira_plugin

    os.environ.pop("JIRA_URL", None)
    os.environ.pop("JIRA_TOKEN", None)
    jira_plugin.JiraPlugin().on_finding(make_finding())  # must not raise


def test_jira_plugin_posts_ticket(monkeypatch):
    from blastradius.plugins.builtin import jira_plugin

    monkeypatch.setenv("JIRA_URL", "https://company.atlassian.net")
    monkeypatch.setenv("JIRA_TOKEN", "tok")
    monkeypatch.setenv("JIRA_PROJECT", "SEC")
    captured = {}

    def fake_post(url, payload, token):
        captured["url"] = url
        captured["payload"] = payload
        captured["token"] = token

    monkeypatch.setattr(jira_plugin, "_post", fake_post)
    jira_plugin.JiraPlugin().on_finding(make_finding())

    assert captured["url"] == "https://company.atlassian.net/rest/api/2/issue"
    assert captured["payload"]["fields"]["project"]["key"] == "SEC"
    assert "SQLI" in captured["payload"]["fields"]["summary"]
    assert captured["token"] == "tok"


def test_linear_plugin_graceful_without_env():
    from blastradius.plugins.builtin import linear_plugin

    os.environ.pop("LINEAR_API_KEY", None)
    linear_plugin.LinearPlugin().on_finding(make_finding())  # must not raise


def test_linear_plugin_posts_issue(monkeypatch):
    from blastradius.plugins.builtin import linear_plugin

    monkeypatch.setenv("LINEAR_API_KEY", "lin-tok")
    captured = {}

    def fake_graphql(query, variables, token):
        captured["variables"] = variables
        captured["token"] = token

    monkeypatch.setattr(linear_plugin, "_graphql", fake_graphql)
    linear_plugin.LinearPlugin().on_finding(make_finding())

    assert "SQLI" in captured["variables"]["title"]
    assert captured["token"] == "lin-tok"


def test_cli_list(monkeypatch, capsys):
    rc = plugins_main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Plugin" in out and "jira" in out and "csv_export" in out


def test_cli_install(tmp_path, monkeypatch):
    plugin_file = tmp_path / "my_plugin.py"
    plugin_file.write_text("from blastradius.plugins.base import BasePlugin\n", encoding="utf-8")
    dest = tmp_path / "dest"
    monkeypatch.setattr("blastradius.plugins.__main__._user_plugin_dir", lambda: dest)
    rc = plugins_main(["install", str(plugin_file)])
    assert rc == 0
    assert (dest / "my_plugin.py").exists()


def test_plugin_events_fire_in_pipeline(tmp_path, monkeypatch):
    from blastradius.pipeline import FullPipeline

    events = []

    class Recorder:
        def on_finding(self, finding):
            events.append("finding")

        def on_patch(self, patch):
            events.append("patch")

        def on_scan_complete(self, results):
            events.append("complete")

    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "name = request.args.get('name')\n"
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n',
        encoding="utf-8",
    )
    pipeline = FullPipeline(
        reports_dir=str(tmp_path / "reports"),
        db=None,
        plugins=Recorder(),
    )
    # disable the default improver + db side effects via monkeypatch of defaults is
    # not needed — Recorder() replaces the loader entirely.
    result = pipeline.run(str(tmp_path))
    assert "finding" in events
    assert "complete" in events
    # sqlite + improver still created internally, which is fine — events are what we assert
    assert result.findings
