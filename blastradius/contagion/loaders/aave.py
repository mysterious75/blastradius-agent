"""Aave V3/V4 collateral-listing loader — canonical on-chain-adjacent risk config.

Reads the keyless AaveKit GraphQL API (``POST https://api.v3.aave.com/graphql``;
docs: https://aave.com/docs/aave-v3/getting-started/graphql) and folds every
market's reserves into the contagion graph:

* ``Token --COLLATERAL_IN--> Market`` for every reserve with
  ``canBeCollateral: true`` (borrow-only reserves are skipped);
* ``Oracle --PRICES--> Token`` from each reserve's ``usdOracleAddress``;
* reserve risk config (LTV, liquidation threshold/bonus, supply cap, eMode,
  paused/frozen) lands on the edge/node ``meta`` so scoring and audit rules
  can consume it.

Schema was mapped by introspection (see ``scripts/probe_aave_*.py``); field
names here are verified live, not guessed.

Conventions (match ``loaders/collateral.py``): stdlib ``urllib`` only, polite
rate-limit, identifying User-Agent, network code never called by tests (the
graph builder takes plain dicts).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ..graph import DeFiContagionGraph
from ..schema import EdgeKind, NodeKind

AAVE_V3_URL = "https://api.v3.aave.com/graphql"
USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 45.0
#: Be polite even though the endpoint is public.
MIN_REQUEST_INTERVAL_S = 0.5

_last_request_at = 0.0

#: Chain ids the loader queries by default (Ethereum + major L2s).
DEFAULT_CHAIN_IDS = [1, 42161, 10, 8453, 137]

_RESERVES_QUERY = """{ markets(request: {chainIds: [%s]}) {
  name address chain { chainId }
  reserves {
    underlyingToken { symbol address }
    usdOracleAddress
    isPaused isFrozen
    supplyInfo { maxLTV { value } liquidationThreshold { value } liquidationBonus { value } canBeCollateral supplyCap { amount { value } } }
    eModeInfo { categoryId label }
  }
} }"""


def _post_graphql(query: str, timeout: float = DEFAULT_TIMEOUT) -> Any:
    global _last_request_at
    wait = MIN_REQUEST_INTERVAL_S - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    body = json.dumps({"query": query}).encode()
    request = urllib.request.Request(
        AAVE_V3_URL, data=body,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    finally:
        _last_request_at = time.monotonic()


def fetch_markets(chain_ids: list[int] | None = None, timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Live Aave markets with full reserve risk config. Network code."""
    ids = ",".join(str(c) for c in (chain_ids or DEFAULT_CHAIN_IDS))
    payload = _post_graphql(_RESERVES_QUERY % ids, timeout=timeout)
    if isinstance(payload, dict) and payload.get("errors"):
        raise RuntimeError(f"Aave GraphQL errors: {json.dumps(payload['errors'])[:300]}")
    return ((payload or {}).get("data") or {}).get("markets") or []


def _fval(node: Any) -> float | None:
    try:
        return float(node.get("value")) if isinstance(node, dict) else None
    except (TypeError, ValueError):
        return None


def build_graph_from_aave(markets: list[dict[str, Any]]) -> DeFiContagionGraph:
    """Fold Aave market dicts (as returned by :func:`fetch_markets`) into a graph.

    Pure function — no network, fully unit-testable.
    """
    graph = DeFiContagionGraph()
    for market in markets:
        market_name = str(market.get("name") or "Aave")
        chain = str(((market.get("chain") or {}).get("chainId")) or "?")
        market_id = f"{market_name} ({chain})"
        # Names double as stable ids here (all lowercase protocol slug).
        graph.add_node(NodeKind.PROTOCOL, "aave", tvl_usd=0.0)
        graph.add_node(NodeKind.CHAIN, chain, tvl_usd=0.0)
        graph.add_node(
            NodeKind.MARKET, market_id, tvl_usd=0.0,
            meta={"address": market.get("address", ""), "source": "aave-v3-graphql"},
        )
        graph.add_edge(EdgeKind.PART_OF, (NodeKind.MARKET, market_id), (NodeKind.PROTOCOL, "aave"))
        graph.add_edge(EdgeKind.DEPLOYED_ON, (NodeKind.PROTOCOL, "aave"), (NodeKind.CHAIN, chain))

        for reserve in market.get("reserves") or []:
            token = (reserve.get("underlyingToken") or {})
            symbol = str(token.get("symbol") or "")
            if not symbol:
                continue
            supply = reserve.get("supplyInfo") or {}
            if not supply.get("canBeCollateral"):
                continue  # borrow-only: not a contagion edge
            graph.add_node(NodeKind.TOKEN, symbol, tvl_usd=0.0,
                           meta={"address": token.get("address", "")})
            graph.add_edge(
                EdgeKind.COLLATERAL_IN, (NodeKind.TOKEN, symbol), (NodeKind.MARKET, market_id),
                meta={
                    "ltv": _fval(supply.get("maxLTV")),
                    "liquidation_threshold": _fval(supply.get("liquidationThreshold")),
                    "liquidation_bonus": _fval(supply.get("liquidationBonus")),
                    "supply_cap": _fval((supply.get("supplyCap") or {}).get("amount")),
                    "paused": bool(reserve.get("isPaused")),
                    "frozen": bool(reserve.get("isFrozen")),
                    "emode": [e.get("label") for e in (reserve.get("eModeInfo") or []) if e.get("label")],
                    "source": "aave-v3-graphql",
                },
            )
            oracle = str(reserve.get("usdOracleAddress") or "")
            if oracle:
                oracle_name = f"aave-oracle:{oracle}"
                graph.add_node(NodeKind.ORACLE, oracle_name, tvl_usd=0.0,
                               meta={"source": "aave-v3-graphql"})
                graph.add_edge(EdgeKind.PRICES, (NodeKind.ORACLE, oracle_name), (NodeKind.TOKEN, symbol))
    return graph
