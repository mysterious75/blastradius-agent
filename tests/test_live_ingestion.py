"""Live ingestion tests — offline.

Network fetchers are monkeypatched. What is tested is the *join* and the
*metadata mapping*, because that mapping is what turns a public API response
into a solvency model. No request leaves these tests.
"""

import json

import pytest

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.loaders import collateral
from blastradius.contagion.schema import EdgeKind, NodeKind
from blastradius.contagion.scoring import score_blast_radius, simulate_token_collapse

POOLS_RESPONSE = {
    "data": [
        {
            "pool": "pool-a",
            "project": "aave-v3",
            "chain": "Ethereum",
            "symbol": "WETH",
            "tvlUsd": 500_000_000.0,
            "apy": 1.5,
            "underlyingTokens": ["0xweth"],
        },
        {
            "pool": "pool-b",
            "project": "aave-v3",
            "chain": "Ethereum",
            "symbol": "USDC-WETH",
            "tvlUsd": 41_000_000.0,
            "apy": 3.0,
            "underlyingTokens": ["0xusdc", "0xweth"],
        },
        {
            # not a lending market -> must be dropped by fetch_lending_markets
            "pool": "pool-c",
            "project": "uniswap-v3",
            "chain": "Ethereum",
            "symbol": "USDC-WETH",
            "tvlUsd": 900_000_000.0,
            "apy": 12.0,
        },
    ]
}

LENDBORROW_RESPONSE = [
    {
        "pool": "pool-a",
        "totalSupplyUsd": 500_000_000.0,
        "totalBorrowUsd": 300_000_000.0,
        "ltv": 0.805,
        "borrowable": True,
        "borrowFactor": None,
        "debtCeilingUsd": None,
        "mintedCoin": None,
        "underlyingTokens": ["0xweth"],
    },
    {
        "pool": "pool-b",
        "totalSupplyUsd": 41_000_000.0,
        "totalBorrowUsd": 30_000_000.0,
        "ltv": 0.88,
        "borrowable": True,
        "borrowFactor": 0.95,
        "debtCeilingUsd": 25_000_000.0,
        "mintedCoin": None,
        "underlyingTokens": ["0xusdc", "0xweth"],
    },
]


@pytest.fixture
def no_network(monkeypatch):
    """Route _get_json at the canned responses; fail loudly on anything else."""

    def fake_get(url, timeout=42.0):
        if url.endswith("/pools"):
            return POOLS_RESPONSE
        if url.endswith("/lendBorrow"):
            return LENDBORROW_RESPONSE
        raise AssertionError(f"unexpected network call in test: {url}")

    monkeypatch.setattr(collateral, "_get_json", fake_get)


# --- fetch_lending_markets --------------------------------------------------


def test_lending_markets_join_on_pool_id(no_network):
    rows = collateral.fetch_lending_markets()
    assert {r["pool_id"] for r in rows} == {"pool-a", "pool-b"}  # pool-c dropped

    a = next(r for r in rows if r["pool_id"] == "pool-a")
    assert a["project"] == "aave-v3"
    assert a["total_supply_usd"] == 500_000_000.0
    assert a["total_borrow_usd"] == 300_000_000.0
    assert a["ltv"] == 0.805
    assert a["underlying_tokens"] == ["0xweth"]


def test_lending_markets_respect_filters(no_network):
    assert collateral.fetch_lending_markets(project="uniswap") == []
    assert {r["pool_id"] for r in collateral.fetch_lending_markets(min_tvl_usd=100_000_000)} == {"pool-a"}
    assert {r["pool_id"] for r in collateral.fetch_lending_markets(chain="ethereum")} == {"pool-a", "pool-b"}


def test_lending_markets_sorted_by_tvl(no_network):
    rows = collateral.fetch_lending_markets()
    assert [r["pool_id"] for r in rows] == ["pool-a", "pool-b"]


# --- build_graph_from_lending_markets --------------------------------------


def test_graph_carries_solvency_metadata(no_network):
    rows = collateral.fetch_lending_markets()
    g = collateral.build_graph_from_lending_markets(rows)
    market = g.backend.node(g.seed_id(NodeKind.MARKET, "aave-v3 WETH (Ethereum)"))

    assert market.meta["token_supplied_usd"] == 500_000_000.0
    assert market.meta["debt_against_token_usd"] == 300_000_000.0
    assert market.meta["backstop_buffer_usd"] == 0.0  # not published by any free API
    assert market.meta["ltv"] == 0.805
    assert market.meta["source"] == "defillama:yields+lendBorrow"


def test_graph_backstop_buffers_can_be_filled(no_network):
    rows = collateral.fetch_lending_markets()
    g = collateral.build_graph_from_lending_markets(
        rows, backstop_buffers={"aave-v3 WETH (Ethereum)": 75_000_000.0}
    )
    market = g.backend.node(g.seed_id(NodeKind.MARKET, "aave-v3 WETH (Ethereum)"))
    assert market.meta["backstop_buffer_usd"] == 75_000_000.0


def test_live_graph_feeds_the_solvency_model(no_network):
    rows = collateral.fetch_lending_markets()
    g = collateral.build_graph_from_lending_markets(rows)

    seed = g.seed_id(NodeKind.TOKEN, "WETH")
    bad = {r.market_id: r for r in simulate_token_collapse(g, seed, price_ratio=0.0)}

    single = bad[g.seed_id(NodeKind.MARKET, "aave-v3 WETH (Ethereum)")]
    assert single.bad_debt_usd == pytest.approx(300_000_000.0)
    assert single.uncovered_loss_usd == pytest.approx(300_000_000.0)  # zero backstop
    assert single.outcome == "UNLIQUIDATABLE"

    # WETH also sits inside the USDC-WETH market
    assert g.seed_id(NodeKind.MARKET, "aave-v3 USDC-WETH (Ethereum)") in bad


def test_live_graph_score_reaches_protocol_and_chain(no_network):
    g = collateral.build_graph_from_lending_markets(collateral.fetch_lending_markets())
    s = score_blast_radius(g, g.seed_id(NodeKind.TOKEN, "WETH"))
    assert s.market_count == 2
    assert s.protocol_count == 1
    assert s.chain_count == 1
    assert s.direct_exposure_usd == pytest.approx(500_000_000.0 + 41_000_000.0)
    assert s.severity in {"MEDIUM", "HIGH", "CRITICAL"}


def test_top_n_keeps_largest(no_network):
    g = collateral.build_graph_from_lending_markets(collateral.fetch_lending_markets(), top_n=1)
    markets = [n for n in g.backend.all_nodes() if n.kind is NodeKind.MARKET]
    assert len(markets) == 1
    assert markets[0].name == "aave-v3 WETH (Ethereum)"


# --- published snapshot ----------------------------------------------------


def test_published_snapshot_is_loadable():
    """docs/data/blast-graph.json must stay a valid graph snapshot."""
    snap = json.load(open("docs/data/blast-graph.json", encoding="utf-8"))
    assert snap["provenance"]["data_source"] == "DeFiLlama"
    assert "derived_fields_note" in snap["provenance"]
    assert "disclaimer" in snap["provenance"]

    g = DeFiContagionGraph.from_json("docs/data/blast-graph.json")
    assert len(g.backend.all_nodes()) == snap["provenance"]["node_count"]
    assert len(g.backend.all_edges()) == snap["provenance"]["edge_count"]


def test_published_snapshot_has_real_markets():
    g = DeFiContagionGraph.from_json("docs/data/blast-graph.json")
    markets = [n for n in g.backend.all_nodes() if n.kind is NodeKind.MARKET]
    assert markets, "published snapshot must contain real markets"
    assert any(n.meta.get("token_supplied_usd", 0) > 0 for n in markets)
    assert any(n.meta.get("source") == "defillama:yields+lendBorrow" for n in markets)
