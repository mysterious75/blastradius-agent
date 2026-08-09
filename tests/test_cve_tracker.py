"""Deduplicator + CVE tracker tests — isolated tmp DB, no network."""

import pytest

from blastradius.db.database import SQLiteDB
from blastradius.db.deduplicator import Deduplicator
from blastradius.cli.cve_tracker import main as tracker_main
from blastradius.hunter.scanner import Finding


@pytest.fixture
def dedup(tmp_path):
    return Deduplicator(db=SQLiteDB(db_path=str(tmp_path / "d.db")))


def make_finding(vuln_type="sqli", payload="SELECT * FROM users", line=5):
    return Finding(file="/repo/app.py", line=line, vuln_type=vuln_type,
                   payload=payload, confidence=0.9, severity="HIGH",
                   cwe="CWE-89", description="d", remediation="r")


def test_fingerprint_deterministic():
    a = Deduplicator.fingerprint(make_finding(), repo="org/repo")
    b = Deduplicator.fingerprint(make_finding(), repo="org/repo")
    c = Deduplicator.fingerprint(make_finding(payload="different"), repo="org/repo")
    d = Deduplicator.fingerprint(make_finding(), repo="other/repo")
    assert a == b and a != c and a != d
    assert len(a) == 64  # sha256 hex


def test_is_duplicate_flow(dedup):
    finding = make_finding()
    assert dedup.is_duplicate(finding, repo="org/repo") is False  # first sight
    assert dedup.is_duplicate(finding, repo="org/repo") is True   # duplicate
    assert dedup.is_duplicate(make_finding(line=6), repo="org/repo") is False  # different line

    with dedup.db._connect() as conn:
        row = conn.execute("SELECT count FROM fingerprints WHERE fingerprint = ?",
                           (Deduplicator.fingerprint(finding, "org/repo"),)).fetchone()
    assert row["count"] == 2


def test_disclosure_status_cycle(dedup):
    finding_id = dedup.db.save_finding(1, make_finding())
    assert dedup.get_disclosure_status(finding_id) == "pending"

    dedup.mark_disclosed(finding_id)
    assert dedup.get_disclosure_status(finding_id) == "submitted"

    dedup.mark_disclosed(finding_id, cve_id="CVE-2026-0001", bounty=500)
    assert dedup.get_disclosure_status(finding_id) == "cve_assigned"

    dedup.mark_fixed(finding_id)
    assert dedup.get_disclosure_status(finding_id) == "fixed"


def test_tracking_rows_and_stats(dedup):
    fid1 = dedup.db.save_finding(1, make_finding())
    fid2 = dedup.db.save_finding(1, make_finding(vuln_type="xss", payload="<script>"))
    dedup.mark_disclosed(fid1, cve_id="CVE-2026-0001", bounty=500)
    dedup.mark_disclosed(fid2, bounty=100)

    rows = dedup.get_tracking_rows()
    assert len(rows) == 2
    assert rows[0]["cve_id"] == "CVE-2026-0001"

    stats = dedup.get_stats()
    assert stats["total_disclosed"] == 2
    assert stats["assigned_cves"] == 1
    assert stats["total_bounty_usd"] == 600.0


def test_avg_fix_time(dedup):
    import datetime

    # disclosed 3 days ago, fixed 1 day ago → fix time = 2 days
    disclosed = (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat(timespec="seconds")
    fixed = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat(timespec="seconds")
    fid = dedup.db.save_finding(1, make_finding())
    dedup.mark_disclosed(fid, cve_id="CVE-2026-0002")
    with dedup.db._connect() as conn:
        conn.execute("UPDATE cve_tracking SET disclosed_at = ?, fixed_at = ? WHERE finding_id = ?",
                     (disclosed, fixed, fid))
    stats = dedup.get_stats()
    assert stats["avg_fix_days"] == pytest.approx(2, abs=1)


def test_cli_update_and_list(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    db = SQLiteDB(db_path=str(db_path))
    fid = db.save_finding(1, make_finding())

    rc = tracker_main(["update", "--id", str(fid), "--cve", "CVE-2026-9999", "--bounty", "750",
                       "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cve_assigned" in out
    assert "CVE-2026-9999" in out

    rc = tracker_main(["list", "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE ID" in out and "Status" in out and "Days Open" in out
    assert "CVE-2026-9999" in out


def test_cli_stats(tmp_path, capsys):
    db_path = tmp_path / "cli.db"
    db = SQLiteDB(db_path=str(db_path))
    fid = db.save_finding(1, make_finding())
    db.save_finding(1, make_finding(payload="y"))
    Deduplicator(db=db).mark_disclosed(fid, cve_id="CVE-2026-1", bounty=1000)

    rc = tracker_main(["stats", "--db", str(db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Total disclosed" in out and "1" in out
    assert "Assigned CVEs" in out
    assert "Total bounty" in out and "1000.0" in out
