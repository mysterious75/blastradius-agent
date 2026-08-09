"""Self-improvement loop tests — isolated data dir, no network."""

import json

import pytest

from blastradius.hunter.scanner import CVEHunter, Finding
from blastradius.learning.improver import SelfImprover


@pytest.fixture
def improver(tmp_path):
    return SelfImprover(data_dir=str(tmp_path))


def make_finding(vuln_type="sqli", file="/repo/app.py", payload="x"):
    return Finding(file=file, line=1, vuln_type=vuln_type, payload=payload,
                   confidence=0.9, severity="HIGH", cwe="CWE-79",
                   description="d", remediation="r")


def test_record_and_read_outcomes(improver):
    improver.record_outcome(make_finding(), was_fp=True, sandbox_result="NOT_EXPLOITABLE")
    improver.record_outcome(make_finding(vuln_type="xss"), was_fp=False,
                            sandbox_result="CONFIRMED_EXPLOITABLE", patch_confidence=100.0)
    outcomes = improver.read_outcomes()
    assert len(outcomes) == 2
    assert outcomes[0]["was_fp"] is True
    assert outcomes[1]["patch_confidence"] == 100.0
    assert improver.outcomes_file.is_file()


def test_analyze_fp_rates(improver):
    for _ in range(4):
        improver.record_outcome(make_finding(vuln_type="xss"), was_fp=True)
    for _ in range(2):
        improver.record_outcome(make_finding(vuln_type="sqli"), was_fp=False,
                                sandbox_result="CONFIRMED_EXPLOITABLE")
    analysis = improver.analyze_patterns()
    assert analysis["sample_size"] == 6
    assert analysis["fp_rates"]["xss"] == 1.0
    assert analysis["fp_rates"]["sqli"] == 0.0


def test_always_fp_file_pattern_detected(improver):
    for _ in range(3):
        improver.record_outcome(make_finding(file="/repo/test_config.js"), was_fp=True)
    analysis = improver.analyze_patterns()
    assert "test_config.js" in analysis["skip_patterns"]


def test_update_rules_raises_threshold_for_high_fp(improver):
    for _ in range(4):
        improver.record_outcome(make_finding(vuln_type="xss"), was_fp=True)
    rules = improver.update_rules()
    assert rules["confidence_thresholds"]["xss"] == 0.95  # 0.7 + 0.5, capped at 0.95
    assert improver.rules_file.is_file()


def test_payload_weight_for_proven_payloads(improver):
    for _ in range(3):
        improver.record_outcome(make_finding(vuln_type="sqli", payload="SELECT * FROM"),
                                was_fp=False, sandbox_result="CONFIRMED_EXPLOITABLE")
    rules = improver.update_rules()
    assert "SELECT *" in rules["payload_weights"]
    assert rules["payload_weights"]["SELECT *"] == 1.2


def test_apply_rules_returns_learned(improver):
    for _ in range(3):
        improver.record_outcome(make_finding(vuln_type="xss"), was_fp=True)
    improver.update_rules()
    applied = improver.apply_rules()
    assert "confidence_thresholds" in applied and "xss" in applied["confidence_thresholds"]


def test_weekly_report(improver):
    for _ in range(4):
        improver.record_outcome(make_finding(vuln_type="xss"), was_fp=True)
    improver.update_rules()
    report = improver.weekly_report()
    assert "Learning Report" in report
    assert "XSS FP rate: 100%" in report
    assert "threshold raised to" in report


def test_empty_improver_is_safe(improver):
    assert improver.analyze_patterns() == {"sample_size": 0}
    assert improver.weekly_report().endswith("0 outcome(s)")
    assert improver.load_rules() == {}


# --- scanner integration -----------------------------------------------------


def test_scanner_uses_learned_threshold(tmp_path, monkeypatch):
    rules_dir = tmp_path / ".blastradius"
    rules_dir.mkdir()
    (rules_dir / "learned_rules.json").write_text(
        json.dumps({"confidence_thresholds": {"sqli": 0.99}}), encoding="utf-8"
    )
    monkeypatch.setenv("BLASTRADIUS_HOME", str(tmp_path))

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.py").write_text(
        "from flask import request\n"
        "name = request.args.get('name')\n"
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n", encoding="utf-8"
    )
    hunter = CVEHunter()  # reads learned rules on startup
    findings = hunter.scan_repo(str(tmp_path / "repo"))
    # sqli concat with a source scores 1.0 (>= 0.99) → still found
    assert any(f.vuln_type == "sqli" for f in findings)


def test_scanner_learned_threshold_can_suppress(tmp_path, monkeypatch):
    rules_dir = tmp_path / ".blastradius"
    rules_dir.mkdir()
    (rules_dir / "learned_rules.json").write_text(
        json.dumps({"confidence_thresholds": {"sqli": 1.5}}), encoding="utf-8"
    )
    monkeypatch.setenv("BLASTRADIUS_HOME", str(tmp_path))

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.py").write_text(
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n", encoding="utf-8"
    )
    hunter = CVEHunter()
    findings = hunter.scan_repo(str(tmp_path / "repo"))
    assert not any(f.vuln_type == "sqli" for f in findings)


def test_scanner_skips_learned_patterns(tmp_path, monkeypatch):
    rules_dir = tmp_path / ".blastradius"
    rules_dir.mkdir()
    (rules_dir / "learned_rules.json").write_text(
        json.dumps({"skip_patterns": ["*.config.js"]}), encoding="utf-8"
    )
    monkeypatch.setenv("BLASTRADIUS_HOME", str(tmp_path))

    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.config.js").write_text(
        "el.innerHTML = payload;\n", encoding="utf-8"
    )
    hunter = CVEHunter()
    assert not hunter.scan_repo(str(tmp_path / "repo"))
