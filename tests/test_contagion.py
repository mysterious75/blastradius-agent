"""Contagion graph + scoring tests — no network, no database."""

import json

import pytest

from blastradius.contagion.cli import main as cli_main
from blastradius.contagion.graph import DeFiContagionGraph, MemoryBackend
from blastradius.contagion.schema import EdgeKind, NodeKind
from blastradius.contagion.scoring import score_blast_radius, simulate_token_collapse

SEED_DATA = "data/seed_kelpdao_case.json"


def _kelpdao_graph() -> DeFiContagionGraph:
    return DeFiContagionGraph.from_json(SEED_DATA)


# --- graph ------------------------------------------------------------------


def test_add_node_merges_tvl_and_metadata():
    g = DeFiContagionGraph()
    g.add_node(NodeKind.TOKEN, "rsETH", tvl_usd=100.0, meta={"issuer": "KelpDAO"})
    g.add_node(NodeKind.TOKEN, "rsETH", tvl_usd=250.0, meta={"category": "LRT"})

    node = g.backend.node(g.seed_id(NodeKind.TOKEN, "rsETH"))
    assert node.tvl_usd == 250.0  # max wins
    assert node.meta["issuer"] == "KelpDAO"
    assert node.meta["category"] == "LRT"


def test_blast_radius_travels_damage_forward():
    g = DeFiContagionGraph()
    g.add_node(NodeKind.TOKEN, "rsETH")
    g.add_node(NodeKind.MARKET, "aave-rseth")
    g.add_node(NodeKind.PROTOCOL, "Aave")
    g.add_node(NodeKind.CHAIN, "Ethereum")
    g.add_edge(EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, "rsETH"), (NodeKind.MARKET, "aave-rseth"))
    g.add_edge(EdgeKind.PART_OF, (NodeKind.MARKET, "aave-rseth"), (NodeKind.PROTOCOL, "Aave"))
    g.add_edge(EdgeKind.DEPLOYED_ON, (NodeKind.PROTOCOL, "Aave"), (NodeKind.CHAIN, "Ethereum"))

    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "rsETH"))
    assert radius.node_count == 3
    assert radius.depth == 3
    assert radius.names_of_kind(NodeKind.MARKET) == ["aave-rseth"]
    assert radius.names_of_kind(NodeKind.PROTOCOL) == ["Aave"]
    assert radius.names_of_kind(NodeKind.CHAIN) == ["Ethereum"]


def test_blast_radius_respects_max_depth():
    g = _kelpdao_graph()
    seed = g.seed_id(NodeKind.TOKEN, "rsETH")
    shallow = g.blast_radius(seed, max_depth=1)
    deep = g.blast_radius(seed, max_depth=5)

    assert shallow.depth == 1
    assert deep.depth >= 3
    assert shallow.node_count < deep.node_count


def test_blast_radius_kind_filter_does_not_prune_traversal():
    g = _kelpdao_graph()
    seed = g.seed_id(NodeKind.TOKEN, "rsETH")
    only_protocols = g.blast_radius(seed, kinds=[NodeKind.PROTOCOL])

    assert {e.kind for e in only_protocols.entries} == {NodeKind.PROTOCOL}
    # Aave sits at hop 2 (market -> protocol), reachable only *through* a market
    # node — so a kind filter that pruned traversal would lose it.
    assert only_protocols.names_of_kind(NodeKind.PROTOCOL) == [
        "Aave",
        "Fluid",
        "SparkLend",
        "Upshift Finance",
    ]


def test_wrapped_copies_and_their_chains_are_impacted():
    g = _kelpdao_graph()
    seed = g.seed_id(NodeKind.TOKEN, "rsETH")
    radius = g.blast_radius(seed)

    assert "rsETH (Base)" in radius.names_of_kind(NodeKind.TOKEN)
    assert "rsETH (Scroll)" in radius.names_of_kind(NodeKind.TOKEN)
    chains = g.impacted_chains(seed)
    assert "Base" in chains and "Scroll" in chains and "Ethereum" in chains


def test_cycle_does_not_loop_forever():
    g = DeFiContagionGraph()
    g.add_node(NodeKind.TOKEN, "a")
    g.add_node(NodeKind.TOKEN, "b")
    # a backs b and b backs a
    g.add_edge(EdgeKind.BACKS, (NodeKind.TOKEN, "a"), (NodeKind.TOKEN, "b"))
    g.add_edge(EdgeKind.BACKS, (NodeKind.TOKEN, "b"), (NodeKind.TOKEN, "a"))

    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "a"))
    assert radius.node_count == 1  # only "b", visited once


def test_oracle_failure_reaches_every_market_it_prices():
    g = _kelpdao_graph()
    radius = g.blast_radius(g.seed_id(NodeKind.ORACLE, "Chainlink-rsETH-ETH"))
    assert radius.names_of_kind(NodeKind.MARKET) == [
        "Aave V3 Ethereum pool (rsETH listing)",
        "Aave V4 Ethereum pool (rsETH listing)",
        "SparkLend Ethereum (rsETH listing)",
    ]


def test_json_round_trip_is_stable():
    g = _kelpdao_graph()
    again = DeFiContagionGraph.from_dict(g.to_dict())
    assert g.to_dict() == again.to_dict()


def test_memory_backend_edge_indexes_stay_consistent():
    b = MemoryBackend()
    g = DeFiContagionGraph(backend=b)
    g.add_node(NodeKind.TOKEN, "rsETH")
    g.add_node(NodeKind.MARKET, "m1")
    g.add_edge(EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, "rsETH"), (NodeKind.MARKET, "m1"))

    token_id = g.seed_id(NodeKind.TOKEN, "rsETH")
    market_id = g.seed_id(NodeKind.MARKET, "m1")
    assert b.successors(token_id)[0].kind is EdgeKind.COLLATERAL_IN
    assert b.predecessors(market_id)[0].kind is EdgeKind.COLLATERAL_IN


# --- scoring ----------------------------------------------------------------


def test_score_reports_severity_and_counts():
    g = _kelpdao_graph()
    score = score_blast_radius(g, g.seed_id(NodeKind.TOKEN, "rsETH"))

    assert score.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert score.market_count == 5
    assert score.protocol_count >= 4
    assert score.direct_exposure_usd == pytest.approx(
        292_000_000 + 85_000_000 + 58_000_000 + 34_000_000 + 19_000_000
    )
    assert score.decayed_tvl_usd <= score.reachable_tvl_usd


def test_bad_debt_matches_kelpdao_mechanic():
    g = _kelpdao_graph()
    rows = simulate_token_collapse(g, g.seed_id(NodeKind.TOKEN, "rsETH"), price_ratio=0.0)
    by_market = {r.market_id: r for r in rows}

    aave = by_market["Market:aave-v3-eth-pool"]
    assert aave.protocol == "Aave"
    assert aave.bad_debt_usd == pytest.approx(240_000_000)
    assert aave.uncovered_loss_usd == pytest.approx(180_000_000)  # 240M debt - 60M umbrella
    assert aave.liquidatable is False
    assert aave.outcome == "UNLIQUIDATABLE"

    upshift = by_market["Market:upshift-vaults"]
    assert upshift.bad_debt_usd == 0.0
    assert upshift.liquidatable is True  # no leverage taken against the token


def test_partial_collapse_proportional():
    g = _kelpdao_graph()
    rows = simulate_token_collapse(g, g.seed_id(NodeKind.TOKEN, "rsETH"), price_ratio=0.5)
    fluid = next(r for r in rows if r.market_id == "Market:fluid-rseth")
    assert fluid.bad_debt_usd == pytest.approx(6_000_000)


def test_price_ratio_bounds():
    g = _kelpdao_graph()
    with pytest.raises(ValueError):
        simulate_token_collapse(g, g.seed_id(NodeKind.TOKEN, "rsETH"), price_ratio=1.5)


# --- CLI --------------------------------------------------------------------


def test_cli_score_runs(capsys):
    assert cli_main(["score", "--token", "rsETH", "--data", SEED_DATA, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["market_count"] == 5


def test_cli_baddebt_runs(capsys):
    assert cli_main(["baddebt", "--token", "rsETH", "--data", SEED_DATA, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(r["outcome"] == "UNLIQUIDATABLE" for r in payload)


def test_cli_map_ascii_runs(capsys):
    assert cli_main(["map", "--token", "rsETH", "--data", SEED_DATA, "--ascii"]) == 0
    out = capsys.readouterr().out
    assert "Token:rsETH" in out
    assert "Aave V3" in out


def test_cli_unknown_token_exits_nonzero():
    assert cli_main(["map", "--token", "NOPE", "--data", SEED_DATA]) == 2


def test_cli_missing_data_exits_nonzero():
    assert cli_main(["map", "--token", "rsETH", "--data", "data/does-not-exist.json"]) == 2
