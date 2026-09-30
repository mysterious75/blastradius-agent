"""Offline tests for LayerZero wiring (registry + Scan pathways + executor rule)."""

from blastradius.contagion.config_audit import ConfigAuditor
from blastradius.contagion.loaders import layerzero


def _metadata():
    return {
        "ethereum": {
            "dvns": {
                "0xAAA": {"canonicalName": "LayerZero Labs", "id": "lz"},
                "0xBBB": {"canonicalName": "Google", "id": "google-cloud"},
            }
        },
        "arbitrum": {
            "dvns": {
                "0xAAA": {"canonicalName": "LayerZero Labs", "id": "lz"},
            }
        },
    }


def _message():
    return {
        "pathway": {
            "id": "1-2-0xO-0xR",
            "srcEid": 1,
            "dstEid": 2,
            "sender": {"address": "0xO", "chain": "ethereum"},
            "receiver": {"address": "0xR", "chain": "arbitrum"},
        },
        "config": {
            "sendLibrary": "0xSL",
            "receiveLibrary": "0xRL",
            "outboundConfig": {
                "confirmations": 15,
                "requiredDVNCount": 2,
                "optionalDVNCount": 1,
                "optionalDVNThreshold": 1,
                "requiredDVNs": ["0xAAA", "0xBBB"],
                "requiredDVNNames": ["LayerZero Labs", "Google"],
                "optionalDVNs": ["0xCCC"],
                "optionalDVNNames": ["Nethermind"],
            },
            "inboundConfig": {
                "confirmations": 5,
                "requiredDVNCount": 1,
                "optionalDVNCount": 0,
                "optionalDVNThreshold": 0,
                "requiredDVNs": ["0xAAA"],
                "requiredDVNNames": ["LayerZero Labs"],
                "optionalDVNs": [],
                "optionalDVNNames": [],
            },
        },
    }


def test_registry_folds_all_chains():
    reg = layerzero.load_dvn_registry(_metadata())
    assert reg["0xaaa"]["operator"] == "LayerZero Labs"
    assert reg["0xbbb"]["operator"] == "Google"
    assert layerzero.load_dvn_registry({}) == {}
    assert layerzero.load_dvn_registry(None) == {}


def test_builder_two_pathways_per_message():
    reg = layerzero.load_dvn_registry(_metadata())
    paths = layerzero.build_pathways_from_messages([_message()], reg)
    assert len(paths) == 2
    out = next(p for p in paths if p["id"].endswith(":outbound"))
    assert out["required_dvn_count"] == 2
    assert out["optional_dvn_threshold"] == 1
    assert out["confirmations"] == 15
    assert out["required_dvn_operators"] == ["LayerZero Labs", "Google"]
    assert out["receive_library"] == "0xSL"  # outbound direction uses sendLibrary
    inn = next(p for p in paths if p["id"].endswith(":inbound"))
    assert inn["required_dvn_count"] == 1
    assert inn["receive_library"] == "0xRL"  # inbound direction uses receiveLibrary


def test_builder_without_registry():
    paths = layerzero.build_pathways_from_messages([_message()])
    assert len(paths) == 2
    assert paths[0]["required_dvn_operators"] == ["", ""]


def test_builder_skips_malformed():
    assert layerzero.build_pathways_from_messages([]) == []
    assert layerzero.build_pathways_from_messages([None, "x", {}]) == []
    assert layerzero.build_pathways_from_messages([{"pathway": {}, "config": {}}]) == []


def test_built_pathways_audit_behaves():
    """Outbound (2-required) is clean; inbound (1-of-1) correctly fires CRITICAL."""
    reg = layerzero.load_dvn_registry(_metadata())
    snap = layerzero.build_audit_snapshot([_message()], reg, target="test")
    report = ConfigAuditor().audit(snap)
    by_target = {}
    for f in report.findings:
        by_target.setdefault(f.target, set()).add(f.rule_id)
    assert "DVN-INSUFFICIENT-REDUNDANCY" not in by_target.get("pathway:1-2-0xO-0xR:outbound", set())
    assert "DVN-INSUFFICIENT-REDUNDANCY" in by_target.get("pathway:1-2-0xO-0xR:inbound", set())


def test_executor_shared_operator_fires():
    snap = {
        "target": "t",
        "pathways": [
            {
                "id": "p1",
                "required_dvn_count": 2,
                "optional_dvn_count": 0,
                "optional_dvn_threshold": 0,
                "required_dvns": ["0xAAA", "0xBBB"],
                "required_dvn_operators": ["LayerZero Labs", "Google"],
                "executor": "0xE",
                "executor_operator": "Google",
                "receive_library": "0xRL",
                "confirmations": 20,
            }
        ],
    }
    report = ConfigAuditor().audit(snap)
    assert "EXECUTOR-SHARED-OPERATOR" in {f.rule_id for f in report.findings}


def test_executor_same_address_fires():
    snap = {
        "target": "t",
        "pathways": [
            {
                "id": "p1",
                "required_dvn_count": 2,
                "optional_dvn_count": 0,
                "optional_dvn_threshold": 0,
                "required_dvns": ["0xAAA", "0xE"],
                "executor": "0xE",
                "receive_library": "0xRL",
                "confirmations": 20,
            }
        ],
    }
    report = ConfigAuditor().audit(snap)
    assert "EXECUTOR-SHARED-OPERATOR" in {f.rule_id for f in report.findings}


def test_executor_absent_no_finding():
    snap = {
        "target": "t",
        "pathways": [
            {
                "id": "p1",
                "required_dvn_count": 2,
                "optional_dvn_count": 0,
                "optional_dvn_threshold": 0,
                "required_dvns": ["0xAAA", "0xBBB"],
                "receive_library": "0xRL",
                "confirmations": 20,
            }
        ],
    }
    report = ConfigAuditor().audit(snap)
    assert "EXECUTOR-SHARED-OPERATOR" not in {f.rule_id for f in report.findings}


def test_executor_independent_no_finding():
    snap = {
        "target": "t",
        "pathways": [
            {
                "id": "p1",
                "required_dvn_count": 2,
                "optional_dvn_count": 0,
                "optional_dvn_threshold": 0,
                "required_dvns": ["0xAAA", "0xBBB"],
                "required_dvn_operators": ["LayerZero Labs", "Google"],
                "executor": "0xE",
                "executor_operator": "Nethermind",
                "receive_library": "0xRL",
                "confirmations": 20,
            }
        ],
    }
    report = ConfigAuditor().audit(snap)
    assert "EXECUTOR-SHARED-OPERATOR" not in {f.rule_id for f in report.findings}


def test_live_snapshot_sample_shape():
    """The saved live Scan message must build without errors (schema-drift guard)."""
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "data" / "ingest" / "lzscan_sample.json"
    if not p.is_file():
        return
    payload = json.loads(p.read_text(encoding="utf-8"))
    snap = layerzero.build_audit_snapshot(payload if isinstance(payload, list) else [payload])
    assert snap["pathways"], "live sample produced no pathways"
