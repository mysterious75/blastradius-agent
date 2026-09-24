"""ConfigAuditor tests — offline, driven by the real KelpDAO config snapshot."""

import json

from blastradius.contagion.cli import main as cli_main
from blastradius.contagion.config_audit import ConfigAuditor

SEED_CONFIG = "data/seed_kelpdao_config.json"


def _seed():
    return json.load(open(SEED_CONFIG, encoding="utf-8"))


def _ids(report):
    return {f.rule_id for f in report.findings}


def test_kelpdao_config_is_flagged_critical():
    """The whole point: a 1-of-1 DVN stack must not pass review."""
    report = ConfigAuditor().audit(_seed())
    assert report.worst_severity == "CRITICAL"
    assert report.passed is False


def test_single_signer_rule_fires_on_every_pathway():
    report = ConfigAuditor().audit(_seed())
    hits = [
        f for f in report.findings if f.rule_id == "DVN-INSUFFICIENT-REDUNDANCY"
    ]
    assert len(hits) == 2  # both pathways in the snapshot
    assert all(f.severity == "CRITICAL" for f in hits)
    assert any("KelpDAO" in f.detail for f in hits)


def test_emergency_pauser_at_1_of_5_is_flagged():
    report = ConfigAuditor().audit(_seed())
    hit = next(f for f in report.findings if f.rule_id == "MULTISIG-THRESHOLD-ONE")
    assert hit.severity == "HIGH"
    assert hit.target == "multisig:emergency-pauser"


def test_single_oracle_feed_is_flagged():
    report = ConfigAuditor().audit(_seed())
    assert "ORACLE-SINGLE-FEED" in _ids(report)
    assert "ORACLE-NO-STALENESS-LIMIT" in _ids(report)
    assert "ORACLE-NO-DEVIATION-LIMIT" in _ids(report)


def test_zero_backstop_on_borrowing_market_is_flagged():
    report = ConfigAuditor().audit(_seed())
    hit = next(f for f in report.findings if f.rule_id == "NO-BACKSTOP-BUFFER")
    assert hit.target == "market:Fluid rsETH market"
    assert hit.severity == "HIGH"


def test_correlated_pathways_share_one_dvn():
    report = ConfigAuditor().audit(_seed())
    hit = next(f for f in report.findings if f.rule_id == "DVN-CORRELATED-PATHWAYS")
    assert set(hit.evidence["pathways"]) == {"ethereum->unichain", "unichain->ethereum"}


def test_admin_and_roles_rules_fire():
    report = ConfigAuditor().audit(_seed())
    ids = _ids(report)
    assert "ADMIN-NO-TIMELOCK" in ids
    assert "NO-LIVE-SENTINEL" in ids
    assert "NO-EMERGENCY-PAUSER" not in ids  # pauser exists (it saved $100M)


def test_hardened_config_passes():
    config = {
        "target": "hardened",
        "pathways": [
            {
                "id": "p1",
                "chain": "Ethereum",
                "confirmations": 20,
                "required_dvn_count": 2,
                "optional_dvn_count": 2,
                "optional_dvn_threshold": 1,
                "required_dvns": ["0xaaa", "0xbbb"],
                "optional_dvns": ["0xccc", "0xddd"],
                "receive_library": "ReceiveUln302",
            }
        ],
        "oracles": [
            {
                "market": "m1",
                "feeds": ["chainlink-rsETH/ETH", "pyth-rsETH/USD"],
                "max_staleness_seconds": 3600,
                "max_deviation_bps": 200,
            }
        ],
        "multisigs": [{"id": "emergency-pauser", "threshold": 3, "signers": 5}],
        "admin": {"address": "0xops", "type": "multisig", "timelock_seconds": 86400},
        "roles": {"pauser": True, "sentinel": True},
        "markets": [{"id": "m1", "name": "m1", "debt_against_token_usd": 1e6, "backstop_buffer_usd": 5e5}],
    }
    report = ConfigAuditor().audit(config)
    assert report.passed is True
    assert report.worst_severity in ("INFO", "LOW", "MEDIUM")


def test_unreachable_threshold_is_critical():
    config = {
        "target": "broken-threshold",
        "pathways": [
            {
                "id": "p1",
                "confirmations": 20,
                "required_dvn_count": 2,
                "optional_dvn_count": 2,
                "optional_dvn_threshold": 5,
                "required_dvns": ["0xaaa", "0xbbb"],
                "optional_dvns": ["0xccc", "0xddd"],
                "receive_library": "ReceiveUln302",
            }
        ],
    }
    report = ConfigAuditor().audit(config)
    assert "DVN-THRESHOLD-UNREACHABLE" in _ids(report)
    assert report.worst_severity == "CRITICAL"


def test_duplicate_dvn_is_not_redundancy():
    config = {
        "target": "duplicate",
        "pathways": [
            {
                "id": "p1",
                "confirmations": 20,
                "required_dvn_count": 2,
                "optional_dvn_count": 0,
                "optional_dvn_threshold": 0,
                "required_dvns": ["0xAAA", "0xAAA"],
                "optional_dvns": [],
                "receive_library": "ReceiveUln302",
            }
        ],
    }
    report = ConfigAuditor().audit(config)
    assert "DVN-DUPLICATE-OPERATOR" in _ids(report)


def test_unreachable_multisig_threshold_is_critical():
    config = {
        "target": "ms",
        "multisigs": [{"id": "ops", "threshold": 7, "signers": 3}],
    }
    report = ConfigAuditor().audit(config)
    assert "MULTISIG-THRESHOLD-UNREACHABLE" in _ids(report)
    assert report.worst_severity == "CRITICAL"


def test_low_confirmations_respects_chain_override():
    base = {
        "target": "confs",
        "pathways": [{"id": "p1", "chain": "Base", "confirmations": 10,
                      "required_dvn_count": 2, "required_dvns": ["0xa", "0xb"],
                      "receive_library": "ReceiveUln302"}],
    }
    strict = ConfigAuditor().audit(base)
    assert "LOW-CONFIRMATIONS" in _ids(strict)

    relaxed = ConfigAuditor(chain_confirmations={"Base": 5}).audit(base)
    assert "LOW-CONFIRMATIONS" not in _ids(relaxed)


def test_empty_config_produces_no_findings():
    report = ConfigAuditor().audit({})
    assert report.findings == []
    assert report.passed is True
    assert report.worst_severity == "INFO"


def test_cli_audit_exits_nonzero_on_bad_config(capsys):
    assert cli_main(["audit", "--config", SEED_CONFIG, "--json", "--quiet"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert payload["worst_severity"] == "CRITICAL"
    assert any(f["rule_id"] == "DVN-INSUFFICIENT-REDUNDANCY" for f in payload["findings"])


def test_cli_audit_missing_config_exits_two():
    assert cli_main(["audit", "--config", "data/nope.json"]) == 2
