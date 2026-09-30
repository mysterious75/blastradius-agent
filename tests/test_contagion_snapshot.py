"""Offline tests for snapshot ingestion (Track A — DeFi dependency graph)."""

import json
from pathlib import Path

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.loaders import snapshot
from blastradius.contagion.schema import EdgeKind, NodeKind


def _write(root: Path, name: str, payload):
    (root / name).write_text(json.dumps(payload), encoding="utf-8")


def test_protocols_multi_chain_edges(tmp_path):
    _write(tmp_path, "defillama_protocols.json", [
        {"slug": "aave", "name": "Aave", "tvl": 1.0e10, "category": "Lending",
         "chains": ["Ethereum", "Arbitrum", "Base"]},
    ])
    g = snapshot.build_graph_from_snapshot(tmp_path, top_n_protocols=10, top_n_markets=0)
    chains = g.blast_radius(g.seed_id(NodeKind.PROTOCOL, "aave")).names_of_kind(NodeKind.CHAIN)
    assert set(chains) == {"Ethereum", "Arbitrum", "Base"}
    # protocol node id is the slug
    assert g.backend.node("Protocol:aave") is not None


def test_oracle_prices_edge(tmp_path):
    _write(tmp_path, "chainlink_feeds_mainnet.json", [
        {"pair": "ETH / USD", "proxyAddress": "0xabc", "path": "eth-usd"},
        {"pair": "weETH / ETH", "proxyAddress": "0xdef"},
    ])
    g = snapshot.build_graph_from_snapshot(tmp_path, top_n_protocols=0, top_n_markets=0)
    # feed ETH/USD prices ETH -> Token:ETH is damaged if the oracle fails
    radius = g.blast_radius(g.seed_id(NodeKind.ORACLE, "chainlink:ETH / USD"))
    assert "ETH" in radius.names_of_kind(NodeKind.TOKEN)
    node = g.backend.node("Oracle:chainlink:ETH / USD")
    assert node is not None and node.meta["source"] == "chainlink"


def test_token_backing_nesting(tmp_path):
    g = snapshot.build_graph_from_snapshot(tmp_path, top_n_protocols=0, top_n_markets=0)
    # stETH is BACKS-> from ETH, so ETH failure damages stETH
    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "ETH"))
    tokens = set(radius.names_of_kind(NodeKind.TOKEN))
    assert {"stETH", "wstETH", "weETH", "rsETH"} <= tokens
    # nesting chains: ETH -> stETH -> wstETH
    radius2 = g.blast_radius(g.seed_id(NodeKind.TOKEN, "stETH"))
    assert "wstETH" in radius2.names_of_kind(NodeKind.TOKEN)


def test_morpho_market_collateral_and_oracle(tmp_path):
    _write(tmp_path, "morpho_blue_markets.json", {
        "data": [{
            "collateralAsset": {"symbol": "wstETH"},
            "loanAsset": {"symbol": "WETH"},
            "oracle": {"address": "0xORACLE"},
            "lltv": "860000000000000000",
            "chain": {"id": 1},
            "state": {"supplyAssetsUsd": 5.0e8, "borrowAssetsUsd": 2.0e8},
        }],
        "cursor": None,
    })
    g = snapshot.build_graph_from_snapshot(tmp_path, top_n_protocols=0, top_n_markets=10)
    # collateral token damages the market
    radius = g.blast_radius(g.seed_id(NodeKind.TOKEN, "wstETH"))
    markets = radius.names_of_kind(NodeKind.MARKET)
    assert any("Morpho" in m for m in markets)
    # oracle failure reaches the market
    rad_o = g.blast_radius("Oracle:morpho-oracle:0xORACLE")
    assert rad_o.node_count >= 1


def test_missing_files_degrade_gracefully(tmp_path):
    g = snapshot.build_graph_from_snapshot(tmp_path)  # empty dir
    assert isinstance(g, DeFiContagionGraph)
    # token backing is code-defined, so it still populates
    assert g.backend.node("Token:ETH") is not None


def test_provenance_reports_presence(tmp_path):
    _write(tmp_path, "chainlink_feeds_mainnet.json", [])
    prov = snapshot.provenance(tmp_path)
    present = {s["file"]: s["present"] for s in prov["sources"]}
    assert present["chainlink_feeds_mainnet.json"] is True
    assert present["morpho_blue_markets.json"] is False


def test_real_snapshot_smoke():
    """If the real data/ingest dir exists, the full build must succeed."""
    root = Path(__file__).resolve().parents[1] / "data" / "ingest"
    if not (root / "defillama_protocols.json").is_file():
        return  # snapshot not present in this checkout — skip silently
    g = snapshot.build_graph_from_snapshot(root, top_n_protocols=50, top_n_markets=25)
    assert len(g.backend.all_nodes()) > 100
    assert len(g.backend.all_edges()) > 100


def test_token_backing_file_matches_builtin(tmp_path):
    """data/token_backing.json must stay in sync with the built-in fallback."""
    from blastradius.contagion.loaders.snapshot import _TOKEN_BACKING_DEFAULT

    repo_file = Path(__file__).resolve().parents[1] / "data" / "token_backing.json"
    assert repo_file.is_file(), "data/token_backing.json must exist"
    file_map = snapshot.load_token_backing_file(repo_file)
    assert file_map == _TOKEN_BACKING_DEFAULT


def test_token_backing_custom_file_overrides(tmp_path):
    custom = tmp_path / "token_backing.json"
    custom.write_text(json.dumps({"backing": {"myLST": "ETH"}}), encoding="utf-8")
    assert snapshot.load_token_backing_file(custom) == {"myLST": "ETH"}


def test_token_backing_missing_file_falls_back(tmp_path):
    from blastradius.contagion.loaders.snapshot import _TOKEN_BACKING_DEFAULT

    assert snapshot.load_token_backing_file(tmp_path / "nope.json") == _TOKEN_BACKING_DEFAULT


def test_token_backing_malformed_file_falls_back(tmp_path):
    from blastradius.contagion.loaders.snapshot import _TOKEN_BACKING_DEFAULT

    bad = tmp_path / "token_backing.json"
    bad.write_text("{not json", encoding="utf-8")
    assert snapshot.load_token_backing_file(bad) == _TOKEN_BACKING_DEFAULT
