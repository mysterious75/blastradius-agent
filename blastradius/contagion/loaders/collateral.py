"""Collateral / dependency ingestion — turn live listings into a contagion graph.

Two loaders, both producing the same ``Token -> Market -> Protocol -> Chain``
shape used by :mod:`blastradius.contagion.graph`:

* :func:`build_graph_from_pools` — live, from DeFiLlama's public yields API.
  Every pool row carries ``project`` / ``chain`` / ``symbol`` / ``tvlUsd``,
  which maps straight onto the node model. No API key.
* :func:`build_graph_from_whitelist` — deterministic, from a protocol's own
  declared collateral listing. Carries per-market ``token_supplied_usd`` /
  ``debt_against_token_usd`` / ``backstop_buffer_usd`` so the bad-debt
  simulation in :mod:`blastradius.contagion.scoring` has what it needs.

This is **read-only data collection** of public protocol metadata — no
transactions, no scanning of third-party systems. Network code lives here so
the graph/scoring core stays offline-testable.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from ..graph import DeFiContagionGraph
from ..schema import EdgeKind, NodeKind

YIELDS_URL = "https://yields.llama.fi/pools"
USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 30.0


def _get_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed hosts
        return json.loads(response.read().decode("utf-8"))


def fetch_pools(
    project: Optional[str] = None,
    chain: Optional[str] = None,
    min_tvl_usd: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Live lending/LP pool rows from DeFiLlama, filtered and TVL-descending.

    ``project`` / ``chain`` matches are case-insensitive; when ``project`` is
    omitted every protocol is returned.
    """
    payload = _get_json(YIELDS_URL, timeout=timeout)
    rows: List[Dict[str, Any]] = []
    for row in (payload or {}).get("data", []) or []:
        tvl = float(row.get("tvlUsd") or 0.0)
        if tvl < min_tvl_usd:
            continue
        if project and project.lower() not in str(row.get("project", "")).lower():
            continue
        if chain and chain.lower() != str(row.get("chain", "")).lower():
            continue
        rows.append(
            {
                "pool_id": str(row.get("pool", "")),
                "project": str(row.get("project", "")),
                "chain": str(row.get("chain", "")),
                "symbol": str(row.get("symbol", "")),
                "tvl_usd": tvl,
                "apy": float(row.get("apy") or 0.0),
            }
        )
    rows.sort(key=lambda r: -r["tvl_usd"])
    return rows


def _split_symbol(symbol: str) -> List[str]:
    """``"USDC-WETH"`` -> ``["USDC", "WETH"]``; single-asset symbols pass through."""
    raw = [p.strip() for p in (symbol or "").replace("/", "-").split("-") if p.strip()]
    return raw or ["UNKNOWN"]


def build_graph_from_pools(
    pools: Iterable[Dict[str, Any]],
    top_n: Optional[int] = None,
) -> DeFiContagionGraph:
    """Fold pool rows into a contagion graph.

    Each pool becomes one ``Market`` with its ``tvl_usd`` set to the pool TVL;
    its underlyings become ``Token`` nodes joined by ``COLLATERAL_IN``; the
    project becomes a ``Protocol`` joined by ``PART_OF``; and the chain is
    joined by ``DEPLOYED_ON``.

    Note this carries *exposure* only — it has no borrow/backstop figures, so
    :func:`~blastradius.contagion.scoring.simulate_token_collapse` will report
    zero bad debt for these markets. Use
    :func:`build_graph_from_whitelist` for solvency numbers.
    """
    graph = DeFiContagionGraph()
    seen_pools: set = set()

    for i, pool in enumerate(pools):
        if top_n is not None and i >= top_n:
            break
        project = pool.get("project") or "unknown"
        chain = pool.get("chain") or "unknown"
        symbol = pool.get("symbol") or "UNKNOWN"
        tvl = float(pool.get("tvl_usd") or 0.0)
        pool_id = pool.get("pool_id") or f"{project}:{chain}:{symbol}"

        market_name = f"{project} {symbol} ({chain})"
        if market_name in seen_pools:
            continue
        seen_pools.add(market_name)

        graph.add_node(NodeKind.MARKET, market_name, tvl_usd=tvl, meta={"pool_id": pool_id})
        graph.add_node(NodeKind.PROTOCOL, project, tvl_usd=0.0)
        graph.add_node(NodeKind.CHAIN, chain, tvl_usd=0.0)
        graph.add_edge(EdgeKind.PART_OF, (NodeKind.MARKET, market_name), (NodeKind.PROTOCOL, project))
        graph.add_edge(EdgeKind.DEPLOYED_ON, (NodeKind.PROTOCOL, project), (NodeKind.CHAIN, chain))

        for token in _split_symbol(symbol):
            graph.add_node(NodeKind.TOKEN, token, tvl_usd=0.0)
            graph.add_edge(
                EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, token), (NodeKind.MARKET, market_name)
            )

    return graph


def build_graph_from_whitelist(payload: Union[str, Path, Dict[str, Any]]) -> DeFiContagionGraph:
    """Build a graph from a declared collateral whitelist snapshot.

    Expected shape (``data/seed_kelpdao_case.json`` is a worked example)::

        {
          "markets": [
            {"id": "aave-v3-eth-pool", "name": "...", "protocol": "Aave",
             "chain": "Ethereum", "tvl_usd": 5.2e9,
             "token_supplied_usd": 2.92e8, "debt_against_token_usd": 2.4e8,
             "backstop_buffer_usd": 6e7, "collateral": ["rsETH"]}
          ],
          "tokens": [{"name": "rsETH", "tvl_usd": 1.07e9, "wrapped_on": ["Base"]}]
        }

    Accepts a dict, or a path to a JSON file. Extra keys are preserved on the
    node ``meta`` so downstream scoring can use them.
    """
    data = payload
    if isinstance(payload, (str, Path)):
        data = json.loads(Path(payload).read_text(encoding="utf-8"))

    graph = DeFiContagionGraph()

    for token in data.get("tokens", []) or []:
        name = str(token["name"])
        graph.add_node(
            NodeKind.TOKEN,
            name,
            tvl_usd=float(token.get("tvl_usd", 0.0)),
            meta={k: v for k, v in token.items() if k not in ("name", "tvl_usd", "wrapped_on")},
        )
        for chain in token.get("wrapped_on", []) or []:
            graph.add_node(NodeKind.CHAIN, str(chain), tvl_usd=0.0)
            graph.add_edge(EdgeKind.WRAPPED_ON, (NodeKind.TOKEN, name), (NodeKind.CHAIN, str(chain)))

    for market in data.get("markets", []) or []:
        name = str(market.get("name") or market["id"])
        protocol = str(market["protocol"])
        chain = str(market.get("chain", "unknown"))
        meta = {
            k: v
            for k, v in market.items()
            if k not in ("id", "name", "protocol", "chain", "tvl_usd", "collateral")
        }
        graph.add_node(NodeKind.MARKET, name, tvl_usd=float(market.get("tvl_usd", 0.0)), meta=meta)
        graph.add_node(NodeKind.PROTOCOL, protocol, tvl_usd=0.0)
        graph.add_node(NodeKind.CHAIN, chain, tvl_usd=0.0)
        graph.add_edge(EdgeKind.PART_OF, (NodeKind.MARKET, name), (NodeKind.PROTOCOL, protocol))
        graph.add_edge(EdgeKind.DEPLOYED_ON, (NodeKind.PROTOCOL, protocol), (NodeKind.CHAIN, chain))

        for token in market.get("collateral", []) or []:
            graph.add_node(NodeKind.TOKEN, str(token), tvl_usd=0.0)
            graph.add_edge(
                EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, str(token)), (NodeKind.MARKET, name)
            )

    return graph


def ingest_whitelist_file(path: Union[str, Path]) -> DeFiContagionGraph:
    """Convenience wrapper: read a whitelist JSON file into a graph."""
    return build_graph_from_whitelist(Path(path))
