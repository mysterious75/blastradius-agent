"""RichDisplay tests — capture console output via StringIO, no network."""

from io import StringIO

import pytest
from rich.console import Console

from blastradius.cli.display import RichDisplay
from blastradius.hunter.scanner import Finding


@pytest.fixture
def display():
    buf = StringIO()
    return RichDisplay(console=Console(file=buf, force_terminal=False)), buf


def make_finding(vuln_type="sqli"):
    return Finding(file="/repo/app.py", line=5, vuln_type=vuln_type,
                   payload="x", confidence=0.95, severity="CRITICAL",
                   cwe="CWE-89", description="d", remediation="r")


def test_banner(display):
    d, buf = display
    d.print_banner()
    out = buf.getvalue()
    assert "BlastRadius Agent" in out
    assert "Autonomous Security Engineer" in out
    assert "v1.0.0" in out


def test_findings_table(display):
    d, buf = display
    d.print_findings_table([make_finding()])
    out = buf.getvalue()
    for header in ("File", "Line", "Type", "Confidence", "Severity", "Status"):
        assert header in out
    assert "sqli" in out
    assert "CRITICAL" in out
    assert "CANDIDATE" in out  # default status


def test_findings_table_status_colors(display):
    d, buf = display
    finding = make_finding()
    d.print_findings_table([finding], statuses={id(finding): "CONFIRMED"})
    assert "CONFIRMED" in buf.getvalue()


def test_scan_progress(display):
    d, buf = display
    with d.scan_progress("flask-admin", total=10) as update:
        update(files=208, findings=12)
    out = buf.getvalue()
    assert "Scanning flask-admin" in out


def test_patch_result_renders_diff(display):
    d, buf = display

    class Patch:
        diff = "-vuln\n+fixed"

    class PR:
        patch = Patch()
        needs_human = False

    d.print_patch_result(PR())
    assert "-vuln" in buf.getvalue() and "+fixed" in buf.getvalue()


def test_patch_result_no_patch(display):
    d, buf = display
    d.print_patch_result(None)
    assert "(no patch available)" in buf.getvalue()


def test_stats_panel(display):
    d, buf = display
    d.print_stats_panel({"total_scans": 5, "confirmed_cves": 2, "patches_generated": 3,
                         "success_rate": 80.0})
    out = buf.getvalue()
    assert "Total Scans" in out
    assert "5" in out and "2" in out and "3" in out and "80.0%" in out


def test_provider_table(display):
    d, buf = display
    d.print_provider_table([
        {"provider": "opencode_go", "model": "deepseek-v4-flash", "ok": True,
         "status": "Connected", "latency": "42ms"},
        {"provider": "anthropic", "model": "—", "ok": False,
         "status": "No API key", "latency": "—"},
    ])
    out = buf.getvalue()
    assert "✅ opencode_go" in out
    assert "deepseek-v4-flash" in out
    assert "❌ anthropic" in out
    assert "No API key" in out


def test_generic_table(display):
    d, buf = display
    d.print_table(["A", "B"], [["1", "2"], ["3", "4"]], title="T")
    out = buf.getvalue()
    assert "A" in out and "B" in out and "1" in out and "T" in out


# --- wiring smoke: hunter CLI banner + table via capsys -----------------------


def test_hunter_cli_uses_display(tmp_path, capsys):
    from blastradius.hunter.cli import main as hunter_main

    (tmp_path / "app.py").write_text(
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n", encoding="utf-8"
    )
    rc = hunter_main(["--target", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "BlastRadius Agent" in out          # banner
    assert "candidate finding(s)" in out       # plain status line kept
    assert "sqli" in out                       # rich findings table
