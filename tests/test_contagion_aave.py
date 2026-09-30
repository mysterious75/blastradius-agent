"""Offline tests for the Aave collateral-listing loader."""

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.loaders import aave
from blastradius.contagion.schema import EdgeKind, NodeKind


def _market():
    return {
        "name": "AaveV3Ethereum",
        "address": "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
        "chain": {"chainId": 1},
        "reserves": [
            {"underlyingToken": {"symbol": "WETH", "address": "0xC02"},
             "usdOracleAddress": "0xO1", "isPaused": False, "isFrozen": False,
             "supplyInfo": {"maxLTV": {"value": "0.8"}, "liquidationThreshold": {"value": "0.825"},
                            "liquidationBonus": {"value": "0.05"}, "canBeCollateral": True,
                            "supplyCap": {"amount": {"value": "100000"}}},
             "eModeInfo": [{"categoryId": 1, "label": "ETH"}]},
            {"underlyingToken": {"symbol": "GHO", "address": "0xG"},
             "usdOracleAddress": "0xO2", "isPaused": False, "isFrozen": False,
             "supplyInfo": {"maxLTV": {"value": "0"}, "liquidationThreshold": {"value": "0"},
                            "liquidationBonus": {"value": "0"}, "canBeCollateral": False,
                            "supplyCap": {"amount": {"value": "0"}}},
             "eModeInfo": []},
        ],
    }


def test_collateral_reserve_gets_edge():
    g = aave.build_graph_from_aave([_market()])
    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "WETH"))
    assert any("AaveV3Ethereum" in n for n in radius.names_of_kind(NodeKind.MARKET))


def test_borrow_only_reserve_gets_no_edge():
    g = aave.build_graph_from_aave([_market()])
    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "GHO"))
    assert radius.names_of_kind(NodeKind.MARKET) == []


def test_oracle_prices_edge():
    g = aave.build_graph_from_aave([_market()])
    assert g.backend.node("Oracle:aave-oracle:0xO1") is not None
    radius = g.blast_radius("Oracle:aave-oracle:0xO1")
    assert "WETH" in radius.names_of_kind(NodeKind.TOKEN)


def test_risk_meta_on_edge():
    g = aave.build_graph_from_aave([_market()])
    edges = [e for e in g.backend.all_edges()
             if e.kind == EdgeKind.COLLATERAL_IN and e.src == "Token:WETH"]
    assert len(edges) == 1
    assert edges[0].meta["ltv"] == 0.8
    assert edges[0].meta["liquidation_threshold"] == 0.825
    assert edges[0].meta["supply_cap"] == 100000.0
    assert edges[0].meta["emode"] == ["ETH"]


def test_market_part_of_protocol_and_chain():
    g = aave.build_graph_from_aave([_market()])
    assert g.backend.node("Protocol:aave") is not None
    assert g.backend.node("Chain:1") is not None


def test_empty_and_malformed_input():
    assert isinstance(aave.build_graph_from_aave([]), DeFiContagionGraph)
    assert isinstance(aave.build_graph_from_aave([{"name": "X"}]), DeFiContagionGraph)
    bad = [{"reserves": [{"underlyingToken": {}}]}]
    assert isinstance(aave.build_graph_from_aave(bad), DeFiContagionGraph)


def test_fval_handles_junk():
    assert aave._fval({"value": "abc"}) is None
    assert aave._fval(None) is None
    assert aave._fval({"value": "0.5"}) == 0.5


def test_live_sample_shape():
    """The saved live sample must build without errors (guards schema drift)."""
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "data" / "ingest" / "aave_reserves_eth.json"
    if not p.is_file():
        return
    payload = json.loads(p.read_text(encoding="utf-8"))
    markets = (payload.get("data") or {}).get("markets") or []
    assert markets, "live sample has no markets"
    g = aave.build_graph_from_aave(markets)
    assert len(g.backend.all_nodes()) > 50
