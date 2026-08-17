"""cve_hunt tests — KEV/EPSS enrichment layer, fully offline (no real network)."""

import json

from blastradius import cve_hunt
from blastradius.cli.main import main as cli_main
from blastradius.hunter.scanner import Finding

KEV_FEED_CANNED = json.dumps(
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "test",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-0001",
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": "Acme Widget SQL Injection",
                "dateAdded": "2021-05-01",
                "shortDescription": "SQL injection in Acme Widget.",
                "requiredAction": "Apply updates.",
                "dueDate": "2021-06-01",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
                "cwes": ["CWE-89"],
            },
            {
                "cveID": "CVE-2021-0002",
                "vendorProject": "OtherCorp",
                "product": "Portal",
                "vulnerabilityName": "OtherCorp Portal Cross-Site Scripting",
                "dateAdded": "2021-06-01",
                "shortDescription": "XSS in Portal.",
                "requiredAction": "Apply updates.",
                "dueDate": "2021-07-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": ["CWE-79"],
            },
        ],
    }
)


def _xss_finding() -> Finding:
    return Finding(
        file="app.py",
        line=3,
        vuln_type="xss",
        payload="innerHTML = q",
        confidence=0.9,
        cwe="CWE-79",
    )


# ---------------------------------------------------------------------------
# KEV parsing
# ---------------------------------------------------------------------------


def test_kev_parse():
    entries = cve_hunt.parse_kev(KEV_FEED_CANNED)
    assert len(entries) == 2
    cves = [e["cveID"] for e in entries]
    assert cves == ["CVE-2021-0001", "CVE-2021-0002"]
    # per-entry fields: cveID / cwes (list) / vulnerabilityName
    assert entries[0]["cwes"] == ["CWE-89"]
    assert entries[0]["vendorProject"] == "Acme"
    assert "SQL Injection" in entries[0]["vulnerabilityName"]
    assert entries[1]["cwes"] == ["CWE-79"]


def test_kev_parse_bare_list_and_garbage():
    # a saved snapshot may be a bare list of entries, not the feed envelope
    bare = json.dumps([{"cveID": "CVE-2021-0003", "cwes": ["CWE-22"], "vulnerabilityName": "x"}])
    assert [e["cveID"] for e in cve_hunt.parse_kev(bare)] == ["CVE-2021-0003"]
    # garbage input must never raise
    assert cve_hunt.parse_kev("not json{") == []
    assert cve_hunt.parse_kev('{"vulnerabilities": 42}') == []


# ---------------------------------------------------------------------------
# Finding -> KEV matching (heuristic)
# ---------------------------------------------------------------------------


def test_match_findings():
    kev = cve_hunt.parse_kev(KEV_FEED_CANNED)
    finding = _xss_finding()
    matches = cve_hunt.match_findings_to_kev([finding], kev=kev)
    assert len(matches) == 1
    assert matches[0]["finding"] is finding
    # one KEV entry, matched via the CWE id
    assert len(matches[0]["kev_cves"]) == 1
    assert matches[0]["kev_cves"][0]["cveID"] == "CVE-2021-0002"


def test_match_findings_keyword_bridge():
    # CWE mismatch but the vulnerabilityName carries the vuln keyword -> still
    # a heuristic candidate (e.g. SQL keyword match)
    kev = cve_hunt.parse_kev(KEV_FEED_CANNED)
    finding = Finding(
        file="db.py",
        line=5,
        vuln_type="sqli",
        payload="q = 'SELECT * FROM users WHERE id=' + uid",
        confidence=0.9,
        cwe="CWE-89",
    )
    matches = cve_hunt.match_findings_to_kev([finding], kev=kev)
    assert len(matches) == 1
    assert matches[0]["kev_cves"][0]["cveID"] == "CVE-2021-0001"


def test_match_findings_no_hits():
    kev = cve_hunt.parse_kev(KEV_FEED_CANNED)
    finding = Finding(
        file="x.go",
        line=2,
        vuln_type="crlf",
        payload='r.Header.Set("X-Loc", v)',
        confidence=0.8,
        cwe="CWE-93",
    )
    assert cve_hunt.match_findings_to_kev([finding], kev=kev) == []


# ---------------------------------------------------------------------------
# EPSS — offline-safe
# ---------------------------------------------------------------------------


def test_epss_offline(monkeypatch):
    def boom(req, timeout=30):
        raise OSError("network unreachable")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert cve_hunt.fetch_epss(["CVE-2021-0001", "CVE-2021-0002"]) == {}
    # empty input never touches the network
    assert cve_hunt.fetch_epss([]) == {}


# ---------------------------------------------------------------------------
# CLI — cvehunt with a saved KEV file (no network)
# ---------------------------------------------------------------------------


VULN_APP_PY = """\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
"""


def test_cli_no_network(tmp_path, monkeypatch, capsys):
    (tmp_path / "vulnerable_app.py").write_text(VULN_APP_PY, encoding="utf-8")

    kev_file = tmp_path / "kev.json"
    kev_file.write_text(KEV_FEED_CANNED, encoding="utf-8")

    # deterministic, offline: fake EPSS answers for the matched CVE
    monkeypatch.setattr(
        "blastradius.cve_hunt.fetch_epss",
        lambda cve_ids, timeout=30: {c: {"epss": 0.975, "percentile": 0.99} for c in cve_ids},
    )

    reports_dir = tmp_path / "reports"
    rc = cli_main(
        [
            "cvehunt",
            "--repo",
            str(tmp_path),
            "--kev-file",
            str(kev_file),
            "--reports-dir",
            str(reports_dir),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-0001" in out  # matched KEV CVE printed in the table
    assert "sqli" in out

    reports = list(reports_dir.glob("*_cvehunt.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["tool"] == "blastradius-cvehunt"
    assert report["kev_source"] == str(kev_file)
    enrich = report["enrichments"]
    assert len(enrich) == 1
    assert enrich[0]["vuln_type"] == "sqli"
    assert enrich[0]["cwe"] == "CWE-89"
    assert enrich[0]["kev_cves"] == ["CVE-2021-0001"]
    assert enrich[0]["epss"]["CVE-2021-0001"]["epss"] == 0.975
