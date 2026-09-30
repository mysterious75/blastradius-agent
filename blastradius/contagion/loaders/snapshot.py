"""Offline snapshot ingestion — build a contagion graph from downloaded data.

Unlike :mod:`~blastradius.contagion.loaders.collateral` (which calls live
DeFiLlama APIs), this loader reads the JSON snapshots committed under
``data/ingest/`` (produced by ``scripts/download_defi_data.py``). It is fully
**offline** and therefore unit-testable, and it adds the graph edges the live
loader does not yet emit:

* ``PRICES``      (Oracle) -> (Market)   — Chainlink/Pyth feed -> market
* ``BACKS``       (Token)  -> (Token)    — LRT/LST nesting (weETH->eETH, ...)
* multi-chain ``DEPLOYED_ON`` from ``currentChainTvls``

Inputs (all optional — the loader degrades gracefully when a file is absent):

    data/ingest/defillama_protocols.json   protocol -> chains + TVL
    data/ingest/chainlink_feeds_mainnet.json  oracle feeds (pair -> proxy)
    data/ingest/pyth_price_feeds.json      oracle feeds (Pyth)
    data/ingest/morpho_blue_markets.json   lending markets (loan/collateral/oracle)
    data/ingest/layerzero_metadata.json    chain deployments (bridge reach)

See ``DATA_ATTRIBUTION.md`` for provenance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..graph import DeFiContagionGraph
from ..schema import EdgeKind, NodeKind

# Tokens that are structurally backed by another token (LRT / LST / wrapped).
# Canonical source is ``data/token_backing.json`` (update the file, not the
# code, when new LSTs/LRTs ship); this dict is the offline fallback when the
# file is absent.
_TOKEN_BACKING_DEFAULT: Dict[str, str] = {
    "wstETH": "stETH",
    "stETH": "ETH",
    "weETH": "eETH",
    "eETH": "ETH",
    "rsETH": "ETH",
    "rETH": "ETH",
    "cbETH": "ETH",
    "ezETH": "ETH",
    "sfrxETH": "frxETH",
    "frxETH": "ETH",
    "ankrETH": "ETH",
    "sETH2": "ETH",
}


def load_token_backing_file(path: Optional[Path] = None) -> Dict[str, str]:
    """Read the backing map from ``data/token_backing.json`` (or a given path).

    Returns the built-in fallback when the file is missing/unreadable so the
    loader keeps working offline and in tests.
    """
    candidate = Path(path) if path else _default_ingest_dir().parent / "token_backing.json"
    data = _read_json(candidate)
    if isinstance(data, dict) and isinstance(data.get("backing"), dict):
        return {str(k): str(v) for k, v in data["backing"].items() if k and v}
    return dict(_TOKEN_BACKING_DEFAULT)


def _default_ingest_dir() -> Path:
    # blastradius/contagion/loaders/snapshot.py -> repo root / data / ingest
    return Path(__file__).resolve().parents[3] / "data" / "ingest"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _base_symbol(pair: str) -> str:
    """``"ETH / USD"`` -> ``"ETH"``; ``"weETH-ETH"`` -> ``"weETH"``."""
    if not pair:
        return ""
    head = pair.replace("-", "/").split("/")[0]
    return head.strip()


# ---------------------------------------------------------------------------
# Individual fold-ins
# ---------------------------------------------------------------------------


def load_protocols(graph: DeFiContagionGraph, data: Iterable[Dict[str, Any]], top_n: int = 200) -> int:
    """Fold DeFiLlama protocol rows into Protocol + Chain nodes (multi-chain)."""
    count = 0
    for i, p in enumerate(data):
        if i >= top_n:
            break
        slug = str(p.get("slug") or p.get("name", "")).lower()
        name = str(p.get("name") or slug)
        if not slug:
            continue
        graph.add_node(NodeKind.PROTOCOL, name, tvl_usd=float(p.get("tvl") or 0.0),
                       meta={"category": p.get("category", ""), "source": "defillama:protocols",
                             "slug": slug}, node_id=f"Protocol:{slug}")
        chains = list(p.get("chains") or ([p.get("chain")] if p.get("chain") else []))
        for chain in chains:
            if not chain:
                continue
            graph.add_node(NodeKind.CHAIN, str(chain), tvl_usd=0.0, node_id=f"Chain:{chain}")
            graph.add_edge(EdgeKind.DEPLOYED_ON, (NodeKind.PROTOCOL, slug), (NodeKind.CHAIN, chain))
        count += 1
    return count


def load_oracles(graph: DeFiContagionGraph, feeds: Iterable[Dict[str, Any]], exchanges: Iterable[Dict[str, Any]] = ()) -> int:
    """Oracle (Chainlink) nodes + ``PRICES`` edges to tokens they quote.

    A feed ``"ETH / USD"`` yields ``Oracle:chainlink:ETH/USD`` and a ``PRICES``
    edge to ``Token:ETH`` (damage: feed fails -> the token it prices is mispriced).
    """
    count = 0
    for feed in list(feeds) + list(exchanges):
        pair = str(feed.get("pair") or feed.get("name") or "")
        proxy = str(feed.get("proxyAddress") or feed.get("feedId") or "")
        if not pair:
            continue
        base = _base_symbol(pair)
        if not base:
            continue
        # Include exchange-rate feeds (LRT/LST) as token-pricing oracles too.
        oracle_name = f"chainlink:{pair}"
        graph.add_node(NodeKind.ORACLE, oracle_name, tvl_usd=0.0,
                       meta={"proxy": proxy, "path": feed.get("path", ""),
                             "heartbeat": feed.get("heartbeat", ""),
                             "source": "chainlink"}, node_id=f"Oracle:{oracle_name}")
        graph.add_node(NodeKind.TOKEN, base, tvl_usd=0.0, node_id=f"Token:{base}")
        graph.add_edge(EdgeKind.PRICES, (NodeKind.ORACLE, oracle_name), (NodeKind.TOKEN, base))
        count += 1
    return count


def load_pyth(graph: DeFiContagionGraph, feeds: Iterable[Dict[str, Any]]) -> int:
    """Pyth oracle nodes -> ``PRICES`` edges."""
    count = 0
    for feed in feeds:
        attrs = feed.get("attributes") or {}
        symbol = str(attrs.get("symbol") or attrs.get("display_symbol") or "")
        feed_id = str(feed.get("id") or "")
        if not symbol:
            continue
        base = symbol.replace("_", "/").split("/")[0].strip()
        oracle_name = f"pyth:{symbol}"
        graph.add_node(NodeKind.ORACLE, oracle_name, tvl_usd=0.0,
                       meta={"feed_id": feed_id, "source": "pyth"}, node_id=f"Oracle:{oracle_name}")
        if base:
            graph.add_node(NodeKind.TOKEN, base, tvl_usd=0.0, node_id=f"Token:{base}")
            graph.add_edge(EdgeKind.PRICES, (NodeKind.ORACLE, oracle_name), (NodeKind.TOKEN, base))
        count += 1
    return count


def load_token_backing(graph: DeFiContagionGraph, backing: Optional[Dict[str, str]] = None) -> int:
    """Token -> Token nesting edges (``BACKS``): LRT/LST backed by underlying.

    With no explicit ``backing`` map, reads ``data/token_backing.json`` (falling
    back to the built-in table when the file is absent).
    """
    mapping = backing if backing is not None else load_token_backing_file()
    count = 0
    for token, underlying in mapping.items():
        graph.add_node(NodeKind.TOKEN, token, tvl_usd=0.0, node_id=f"Token:{token}")
        graph.add_node(NodeKind.TOKEN, underlying, tvl_usd=0.0, node_id=f"Token:{underlying}")
        graph.add_edge(EdgeKind.BACKS, (NodeKind.TOKEN, underlying), (NodeKind.TOKEN, token))
        count += 1
    return count


def load_morpho_markets(graph: DeFiContagionGraph, markets: Iterable[Dict[str, Any]], top_n: int = 100) -> int:
    """Morpho Blue markets -> Market nodes with collateral + oracle edges."""
    count = 0
    for i, m in enumerate(markets):
        if i >= top_n:
            break
        collateral = m.get("collateralAsset") or {}
        loan = m.get("loanAsset") or {}
        oracle = m.get("oracle") or {}
        coll_sym = str(collateral.get("symbol") or "")
        loan_sym = str(loan.get("symbol") or "")
        if not coll_sym and not loan_sym:
            continue
        market_name = f"Morpho {loan_sym}/{coll_sym} ({m.get('chain', {}).get('id', '?')})"
        state = m.get("state") or {}
        supply = float((state.get("supplyAssetsUsd") or 0) or 0)
        borrow = float((state.get("borrowAssetsUsd") or 0) or 0)
        graph.add_node(
            NodeKind.MARKET, market_name, tvl_usd=supply,
            meta={"debt_against_token_usd": borrow, "lltv": m.get("lltv"),
                  "token_supplied_usd": supply, "backstop_buffer_usd": 0.0,
                  "source": "morpho"},
            node_id=f"Market:{market_name}",
        )
        graph.add_node(NodeKind.PROTOCOL, "Morpho", tvl_usd=0.0, node_id="Protocol:morpho")
        graph.add_edge(EdgeKind.PART_OF, (NodeKind.MARKET, market_name), (NodeKind.PROTOCOL, "Morpho"))
        if coll_sym:
            graph.add_node(NodeKind.TOKEN, coll_sym, tvl_usd=0.0, node_id=f"Token:{coll_sym}")
            graph.add_edge(EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, coll_sym), (NodeKind.MARKET, market_name))
        if oracle.get("address"):
            oracle_name = f"morpho-oracle:{oracle['address']}"
            graph.add_node(NodeKind.ORACLE, oracle_name, tvl_usd=0.0,
                           meta={"source": "morpho"}, node_id=f"Oracle:{oracle_name}")
            graph.add_edge(EdgeKind.PRICES, (NodeKind.ORACLE, oracle_name), (NodeKind.MARKET, market_name))
        count += 1
    return count


# ---------------------------------------------------------------------------
# Whole-snapshot build
# ---------------------------------------------------------------------------


def build_graph_from_snapshot(ingest_dir: Optional[Path] = None, top_n_protocols: int = 200, top_n_markets: int = 100) -> DeFiContagionGraph:
    """Build a contagion graph from every available ``data/ingest`` snapshot.

    Each input is optional; missing files are simply skipped, so the function
    works offline and in tests with a partial directory.
    """
    root = Path(ingest_dir) if ingest_dir else _default_ingest_dir()
    graph = DeFiContagionGraph()

    protocols = _read_json(root / "defillama_protocols.json") or []
    load_protocols(graph, protocols, top_n=top_n_protocols)

    feeds = _read_json(root / "chainlink_feeds_mainnet.json") or []
    load_oracles(graph, feeds)

    pyth = _read_json(root / "pyth_price_feeds.json") or []
    load_pyth(graph, pyth)

    load_token_backing(graph)

    morpho = _read_json(root / "morpho_blue_markets.json") or {}
    morpho_rows = morpho.get("data", []) if isinstance(morpho, dict) else []
    load_morpho_markets(graph, morpho_rows, top_n=top_n_markets)

    return graph


def provenance(ingest_dir: Optional[Path] = None) -> Dict[str, Any]:
    """List which snapshot files are present (for the graph's provenance block)."""
    root = Path(ingest_dir) if ingest_dir else _default_ingest_dir()
    out: Dict[str, Any] = {"sources": []}
    for name in (
        "defillama_protocols.json",
        "chainlink_feeds_mainnet.json",
        "pyth_price_feeds.json",
        "morpho_blue_markets.json",
        "layerzero_metadata.json",
    ):
        path = root / name
        out["sources"].append({"file": name, "present": path.is_file(),
                               "bytes": path.stat().st_size if path.is_file() else 0})
    return out
