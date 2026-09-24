"""Ingestion tests — offline. Synthetic pool rows and whitelist snapshots.

Network loaders (``fetch_pools``) are deliberately not exercised here; what is
tested is the *mapping* from a listing into the contagion graph, because that
mapping is the data asset.
"""

import json

import pytest

from blastradius.contagion.cli import main as cli_main
from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.loaders.collateral import (
    _split_symbol,
    build_graph_from_pools,
    build_graph_from_whitelist,
)
from blastradius.contagion.schema import EdgeKind, NodeKind
from blastradius.contagion.scoring import score_blast_radius, simulate_token_collapse

POOL_FIXTURE = [
    {
        "pool_id": "aaaa-bbbb",
        "project": "aave-v3",
        "chain": "Ethereum",
        "symbol": "USDC",
        "tvl_usd": 500_000_000.0,
        "apy": 3.2,
    },
    {
        "pool_id": "cccc-dddd",
        "project": "aave-v3",
        "chain": "Base",
        "symbol": "WETH-rsETH",
        "tvl_usd": 41_000_000.0,
        "apy": 4.1,
    },
    {
        "pool_id": "eeee-ffff",
        "project": "sparklend",
        "chain": "Ethereum",
        "symbol": "DAI",
        "tvl_usd": 120_000_000.0,
        "apy": 2.7,
    },
]

WHITELIST_FIXTURE = {
    "tokens": [{"name": "rsETH", "tvl_usd": 1_070_000_000.0, "wrapped_on": ["Base"]}],
    "markets": [
        {
            "id": "aave-v3-eth-pool",
            "name": "Aave V3 Ethereum pool (rsETH listing)",
            "protocol": "Aave",
            "chain": "Ethereum",
            "tvl_usd": 5_200_000_000.0,
            "token_supplied_usd": 292_000_000.0,
            "debt_against_token_usd": 240_000_000.0,
            "backstop_buffer_usd": 60_000_000.0,
            "collateral": ["rsETH"],
        }
    ],
}


# --- symbol handling --------------------------------------------------------


@pytest.mark.parametrize(
    "symbol,expected",
    [
        ("USDC", ["USDC"]),
        ("WETH-rsETH", ["WETH", "rsETH"]),
        ("USDC/WETH", ["USDC", "WETH"]),
        ("", ["UNKNOWN"]),
    ],
)
def test_split_symbol(symbol, expected):
    assert _split_symbol(symbol) == expected


# --- pools -> graph ---------------------------------------------------------


def test_pools_become_markets_protocols_chains():
    g = build_graph_from_pools(POOL_FIXTURE)

    assert g.backend.node(g.seed_id(NodeKind.MARKET, "aave-v3 USDC (Ethereum)"))
    assert g.backend.node(g.seed_id(NodeKind.PROTOCOL, "aave-v3"))
    assert g.backend.node(g.seed_id(NodeKind.CHAIN, "Base"))

    # LP symbols split into their underlyings, each linked as collateral.
    # COLLATERAL_IN runs Token -> Market, so the tokens are the predecessors' src.
    market = g.seed_id(NodeKind.MARKET, "aave-v3 WETH-rsETH (Base)")
    collateral = {
        e.src for e in g.backend.predecessors(market, kind=EdgeKind.COLLATERAL_IN)
    }
    assert collateral == {
        g.seed_id(NodeKind.TOKEN, "WETH"),
        g.seed_id(NodeKind.TOKEN, "rsETH"),
    }


def test_pool_blast_radius_reaches_protocol_and_chain():
    g = build_graph_from_pools(POOL_FIXTURE)
    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "rsETH"))
    assert radius.names_of_kind(NodeKind.MARKET) == ["aave-v3 WETH-rsETH (Base)"]
    assert radius.names_of_kind(NodeKind.PROTOCOL) == ["aave-v3"]
    assert "Base" in radius.names_of_kind(NodeKind.CHAIN)


def test_pools_top_n_limits_markets():
    g = build_graph_from_pools(POOL_FIXTURE, top_n=1)
    markets = [n for n in g.backend.all_nodes() if n.kind is NodeKind.MARKET]
    assert len(markets) == 1
    assert markets[0].tvl_usd == 500_000_000.0  # TVL-descending keeps the largest


def test_pools_dedupe_identical_market_names():
    g = build_graph_from_pools(POOL_FIXTURE + [POOL_FIXTURE[0]])
    markets = [n for n in g.backend.all_nodes() if n.kind is NodeKind.MARKET]
    assert len(markets) == 3


def test_pool_graph_has_no_solvency_numbers():
    """Exposure only — bad debt must read as zero without borrow metadata."""
    g = build_graph_from_pools(POOL_FIXTURE)
    rows = simulate_token_collapse(g, g.seed_id(NodeKind.TOKEN, "rsETH"))
    assert rows != []
    assert all(r.bad_debt_usd == 0.0 for r in rows)


# --- whitelist -> graph -----------------------------------------------------


def test_whitelist_builds_full_model():
    g = build_graph_from_whitelist(WHITELIST_FIXTURE)
    seed = g.seed_id(NodeKind.TOKEN, "rsETH")

    radius = g.blast_radius(seed)
    assert radius.names_of_kind(NodeKind.MARKET) == ["Aave V3 Ethereum pool (rsETH listing)"]
    assert radius.names_of_kind(NodeKind.PROTOCOL) == ["Aave"]
    assert g.impacted_chains(seed) == ["Base", "Ethereum"]


def test_whitelist_carries_solvency_numbers():
    g = build_graph_from_whitelist(WHITELIST_FIXTURE)
    rows = simulate_token_collapse(g, g.seed_id(NodeKind.TOKEN, "rsETH"), price_ratio=0.0)
    assert len(rows) == 1
    assert rows[0].bad_debt_usd == pytest.approx(240_000_000.0)
    assert rows[0].uncovered_loss_usd == pytest.approx(180_000_000.0)
    assert rows[0].outcome == "UNLIQUIDATABLE"


def test_whitelist_score_is_critical():
    g = build_graph_from_whitelist(WHITELIST_FIXTURE)
    score = score_blast_radius(g, g.seed_id(NodeKind.TOKEN, "rsETH"))
    assert score.market_count == 1
    assert score.severity in {"HIGH", "CRITICAL"}


def test_whitelist_accepts_a_path(tmp_path):
    p = tmp_path / "listing.json"
    p.write_text(json.dumps(WHITELIST_FIXTURE), encoding="utf-8")
    g = build_graph_from_whitelist(str(p))
    assert g.backend.node(g.seed_id(NodeKind.TOKEN, "rsETH"))


def test_whitelist_preserves_extra_metadata():
    payload = json.loads(json.dumps(WHITELIST_FIXTURE))
    payload["markets"][0]["ltv_bps"] = 7250
    g = build_graph_from_whitelist(payload)
    market = g.backend.node(g.seed_id(NodeKind.MARKET, "Aave V3 Ethereum pool (rsETH listing)"))
    assert market.meta["ltv_bps"] == 7250


# --- CLI --------------------------------------------------------------------


def test_cli_ingest_whitelist_writes_graph(tmp_path, capsys):
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps(WHITELIST_FIXTURE), encoding="utf-8")
    out = tmp_path / "graph.json"

    assert (
        cli_main(["ingest", "--source", "whitelist", "--data", str(listing), "--out", str(out)])
        == 0
    )
    assert out.is_file()
    assert "ingested whitelist snapshot" in capsys.readouterr().out

    # round-trip through the map command proves the output is a valid snapshot
    assert cli_main(["map", "--token", "rsETH", "--data", str(out), "--json"]) == 0


def test_cli_ingest_whitelist_requires_data():
    assert cli_main(["ingest", "--source", "whitelist"]) == 2
