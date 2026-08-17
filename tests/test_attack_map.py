"""MITRE ATT&CK mapping tests — offline, no network."""

from types import SimpleNamespace

from blastradius.reporting.attack_map import attack_for, load_cwe_to_attack


def test_load_mapping():
    mapping = load_cwe_to_attack()
    assert len(mapping) >= 30
    for cwe, technique in mapping.items():
        assert technique["id"].startswith("T")
        assert technique["name"]


def test_mapping_covers_scanner_cwes():
    # Every CWE used by hunter/scanner.py VULN_META must be mappable.
    scanner_cwes = {
        "CWE-89",
        "CWE-79",
        "CWE-918",
        "CWE-639",
        "CWE-1336",
        "CWE-611",
        "CWE-347",
        "CWE-943",
        "CWE-798",
        "CWE-502",
        "CWE-78",
        "CWE-22",
        "CWE-93",
        "CWE-287",
        "CWE-1321",
        "CWE-94",
        "CWE-706",
        "CWE-710",
    }
    mapping = load_cwe_to_attack()
    missing = scanner_cwes - set(mapping)
    assert not missing, f"no ATT&CK row for {sorted(missing)}"


def test_attack_for_finding():
    from blastradius.hunter.scanner import Finding

    finding = Finding(
        file="a.py",
        line=1,
        vuln_type="xss",
        payload="x",
        confidence=0.95,
        severity="HIGH",
        cwe="CWE-79",
    )
    techniques = attack_for(finding)
    assert any(t["id"] == "T1059.007" for t in techniques)

    unknown = Finding(file="b.py", line=1, vuln_type="unknown", payload="p", confidence=0.1)
    assert attack_for(unknown) == []


def test_attack_for_dict_and_vuln_type_fallback():
    enabled = attack_for({"vuln_type": "sqli"})
    assert any(t["id"] == "T1190" for t in enabled)


def test_summary_includes_attack(tmp_path):
    from blastradius.hunter.scanner import Finding
    from blastradius.reporting.summary import SummaryReporter

    finding = Finding(
        file="a.py",
        line=1,
        vuln_type="xss",
        payload="x",
        confidence=0.95,
        severity="HIGH",
        cwe="CWE-79",
        description="d",
        remediation="r",
    )
    # BlastRadius-free fake PipelineResult (summary only needs these fields)
    result = SimpleNamespace(
        target="org/demo",
        findings=[finding],
        patches=[],
        reports=[],
        blast_radius=None,
        files_scanned=1,
        confirmed=[finding],
        dependencies=[],
    )
    path = SummaryReporter().save_summary(result, str(tmp_path))
    md = path.read_text(encoding="utf-8")
    assert "ATT&CK" in md
    assert "T1059.007" in md


def test_exporter_includes_techniques(tmp_path):
    from blastradius.export.exporter import FindingsExporter

    findings = [
        {
            "file": "views.js",
            "line": 7,
            "vuln_type": "xss",
            "severity": "HIGH",
            "payload": "el.innerHTML = data;",
            "description": "DOM XSS",
            "cwe": "CWE-79",
        }
    ]
    out = tmp_path / "f.sarif"
    FindingsExporter(findings).export_sarif(str(out))

    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert "techniques" in rule["properties"]
    assert "T1059.007" in rule["properties"]["techniques"]
