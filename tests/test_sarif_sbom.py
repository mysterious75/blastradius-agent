"""SARIF 2.1.0 + CycloneDX SBOM export tests — stdlib only, no network."""

import hashlib
import json

import pytest

from blastradius.export.exporter import FindingsExporter

FINDING = {
    "repo": "org/demo",
    "file": "src/app.py",
    "line": 42,
    "vuln_type": "sqli",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "confidence": 0.9,
    "payload": 'query = "SELECT * FROM users WHERE name = \'" + name + "\'"',
    "description": "SQL injection in search",
    "cwe": "CWE-89",
    "remediation": "parameterize",
    "patch_diff": "-a\n+b",
}


def _export_sarif(findings, tmp_path, name="f.sarif"):
    out = tmp_path / name
    FindingsExporter(findings).export_sarif(str(out))
    return json.loads(out.read_text(encoding="utf-8"))


def test_sarif_21_rule_and_result_enrichment(tmp_path):
    sarif = _export_sarif([FINDING], tmp_path)
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["semanticVersion"] == "1.0.0"
    rule = driver["rules"][0]
    assert rule["properties"]["security-severity"] == 9.0
    assert rule["properties"]["precision"] == "high"  # confidence 0.9 >= 0.85
    assert rule["properties"]["tags"] == ["sqli"]
    assert rule["fullDescription"]["text"]
    assert rule["help"]["text"]
    assert rule["help"]["markdown"]
    result = sarif["runs"][0]["results"][0]
    fp = result["partialFingerprints"]["primaryLocationLineHash"]
    assert len(fp) == 32
    int(fp, 16)  # is hex
    assert result["fixes"]
    fix = result["fixes"][0]
    assert fix["artifactChanges"][0]["artifactLocation"]["uri"] == "src/app.py"
    assert fix["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"] == "-a\n+b"


def test_sarif_fingerprint_is_stable_across_runs(tmp_path):
    first = _export_sarif([FINDING], tmp_path, "a.sarif")
    second = _export_sarif([FINDING], tmp_path, "b.sarif")
    h1 = first["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    h2 = second["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert h1 == h2
    expected = hashlib.sha256(
        "src/app.py42sqli{}".format(FINDING["payload"]).encode("utf-8")
    ).hexdigest()[:32]
    assert h1 == expected


def test_sarif_no_fixes_without_patch_diff(tmp_path):
    finding = dict(FINDING)
    del finding["patch_diff"]
    sarif = _export_sarif([finding], tmp_path)
    assert "fixes" not in sarif["runs"][0]["results"][0]


def test_sarif_precision_medium_for_low_confidence(tmp_path):
    finding = dict(FINDING)
    finding["confidence"] = 0.5
    sarif = _export_sarif([finding], tmp_path)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["precision"] == "medium"


def test_sbom_metadata_only(tmp_path):
    out = tmp_path / "sbom.json"
    FindingsExporter([]).export_sbom_cyclonedx(str(out))
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["version"] == 1
    assert bom["metadata"]["tools"] == [{"name": "BlastRadius", "version": "1.0.0"}]
    assert bom["metadata"]["component"]["type"] == "application"
    assert bom["metadata"]["component"]["name"] == "blastradius-agent"
    assert "components" not in bom


def test_sbom_with_deps(tmp_path):
    deps = [
        ("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        ("flask", "3.0.0", "pkg:pypi/flask@3.0.0"),
    ]
    out = tmp_path / "sbom.json"
    FindingsExporter([]).export_sbom_cyclonedx(str(out), deps=deps)
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["metadata"]["tools"]
    assert len(bom["components"]) == 2
    assert bom["components"][0] == {
        "type": "library",
        "name": "requests",
        "version": "2.31.0",
        "purl": "pkg:pypi/requests@2.31.0",
    }


@pytest.mark.parametrize("fmt", ["sarif", "sarif2"])
def test_cli_sarif_formats(tmp_path, fmt):
    from blastradius.export.cli import main as export_main

    src = tmp_path / "in.json"
    src.write_text(json.dumps([FINDING]), encoding="utf-8")
    out = tmp_path / "out.sarif"
    rc = export_main(["--format", fmt, "--output", str(out), "--input", str(src)])
    assert rc == 0
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_cli_sbom(tmp_path):
    from blastradius.export.cli import main as export_main

    src = tmp_path / "in.json"
    src.write_text(json.dumps([]), encoding="utf-8")
    out = tmp_path / "out.json"
    rc = export_main(["--format", "sbom", "--output", str(out), "--input", str(src)])
    assert rc == 0
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
