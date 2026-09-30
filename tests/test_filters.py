"""Shared FP-filter tests (vendored/tests/docs/minified)."""

from blastradius.filters import FP_PATH_PARTS, fp_filter
from blastradius.hunter.scanner import Finding


def _finding(path):
    return Finding(
        file=path,
        line=1,
        vuln_type="xss",
        payload="x",
        confidence=0.9,
        severity="HIGH",
        cwe="CWE-79",
        description="d",
        remediation="r",
    )


def test_drops_vendored_dirs():
    for d in ("node_modules", "vendor", "dist", "docs", "tests", "examples"):
        assert fp_filter([_finding(f"/repo/{d}/a.js")]) == [], d


def test_drops_minified():
    assert fp_filter([_finding("/repo/app.min.js")]) == []
    assert fp_filter([_finding("/repo/jquery.min.js")]) == []


def test_keeps_real_code():
    assert len(fp_filter([_finding("/repo/src/app.py")])) == 1
    assert len(fp_filter([_finding("/repo/lessons/SqlLesson.java")])) == 1


def test_shared_with_autohunt():
    from blastradius.recon import auto_hunt as ah

    assert ah.fp_filter is fp_filter
    assert ah.FP_PATH_PARTS == FP_PATH_PARTS


def test_hunter_cli_applies_filter(tmp_path, capsys):
    from blastradius.hunter import cli as hunter_cli

    (tmp_path / "app.py").write_text("x = 1\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.js").write_text("el.innerHTML = payload;\n")
    rc = hunter_cli.main(
        ["--target", str(tmp_path), "--no-fp-filter", "--reports-dir", str(tmp_path / "rep")]
    )
    assert rc in (0, 1)
    out = capsys.readouterr().out
    assert "FP filter" not in out  # disabled: no filter line


def test_hunter_cli_reports_dropped(tmp_path, capsys):
    from blastradius.hunter import cli as hunter_cli

    (tmp_path / "app.py").write_text("x = 1\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.js").write_text("el.innerHTML = payload;\n")
    hunter_cli.main(["--target", str(tmp_path), "--reports-dir", str(tmp_path / "rep")])
    out = capsys.readouterr().out
    assert "FP filter dropped" in out or "candidate finding" in out
