"""Collateral / dependency ingestion — real listings into a contagion graph.

All live data comes from **DeFiLlama's free public JSON APIs** (open-source
project, no API key, documented endpoints). Nothing here scrapes HTML or
touches a third-party system beyond those published APIs; requests are
rate-limited and carry an identifying User-Agent. See ``DATA_ATTRIBUTION.md``.

Three loaders, all producing the ``Token -> Market -> Protocol -> Chain`` shape
used by :mod:`blastradius.contagion.graph`:

* :func:`fetch_lending_markets` + :func:`build_graph_from_lending_markets` —
  **the real one.** Joins ``/pools`` (project, chain, symbol, TVL) with
  ``/lendBorrow`` (supply, borrow, LTV, borrowable, debt ceiling) on pool id.
  This is what gives :func:`~blastradius.contagion.scoring.simulate_token_collapse`
  genuine solvency numbers.
* :func:`build_graph_from_pools` — exposure only (no borrow figures).
* :func:`build_graph_from_whitelist` — deterministic, from a protocol's own
  declared listing; the only offline path, used by tests and for hand-curated
  risk figures such as backstop buffers (which no free API publishes).

Known gap, stated plainly: **backstop / safety-module balances are not in any
free API.** Markets built from live data carry ``backstop_buffer_usd = 0``,
which makes ``uncovered_loss_usd`` an upper bound. Pass
``backstop_buffers={...}`` to fill them in from on-chain reads.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from ..graph import DeFiContagionGraph
from ..schema import EdgeKind, NodeKind

POOLS_URL = "https://yields.llama.fi/pools"
LENDBORROW_URL = "https://yields.llama.fi/lendBorrow"
PROTOCOL_URL = "https://api.llama.fi/protocol/{slug}"
USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 45.0
#: Be polite even though these endpoints are public.
MIN_REQUEST_INTERVAL_S = 0.5

_last_request_at = 0.0


def _get_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> Any:
    global _last_request_at
    wait = MIN_REQUEST_INTERVAL_S - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed hosts
            return json.loads(response.read().decode("utf-8"))
    finally:
        _last_request_at = time.monotonic()


def _split_symbol(symbol: str) -> List[str]:
    """``"USDC-WETH"`` -> ``["USDC", "WETH"]``; single-asset symbols pass through."""
    raw = [p.strip() for p in (symbol or "").replace("/", "-").split("-") if p.strip()]
    return raw or ["UNKNOWN"]


# ---------------------------------------------------------------------------
# Live fetchers
# ---------------------------------------------------------------------------


def fetch_pools(
    project: Optional[str] = None,
    chain: Optional[str] = None,
    min_tvl_usd: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Live pool rows from DeFiLlama, filtered and TVL-descending.

    Exposure only — see :func:`fetch_lending_markets` for supply/borrow.
    """
    payload = _get_json(POOLS_URL, timeout=timeout)
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
                "pool_meta": str(row.get("poolMeta") or ""),
                "tvl_usd": tvl,
                "apy": float(row.get("apy") or 0.0),
                "underlying_tokens": list(row.get("underlyingTokens") or []),
            }
        )
    rows.sort(key=lambda r: -r["tvl_usd"])
    return rows


def fetch_lend_borrow(timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Dict[str, Any]]:
    """Live lending book keyed by pool id: supply, borrow, LTV, ceilings."""
    payload = _get_json(LENDBORROW_URL, timeout=timeout)
    out: Dict[str, Dict[str, Any]] = {}
    for row in payload or []:
        out[str(row.get("pool", ""))] = {
            "total_supply_usd": float(row.get("totalSupplyUsd") or 0.0),
            "total_borrow_usd": float(row.get("totalBorrowUsd") or 0.0),
            "ltv": row.get("ltv"),
            "borrowable": row.get("borrowable"),
            "borrow_factor": row.get("borrowFactor"),
            "debt_ceiling_usd": row.get("debtCeilingUsd"),
            "minted_coin": row.get("mintedCoin"),
            "underlying_tokens": list(row.get("underlyingTokens") or []),
        }
    return out


def fetch_lending_markets(
    project: Optional[str] = None,
    chain: Optional[str] = None,
    min_tvl_usd: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Real lending markets: DeFiLlama ``/pools`` joined with ``/lendBorrow``.

    Only pools that appear in the lending book are returned — those are the
    ones with an actual collateral listing and outstanding debt. Each row
    carries everything the bad-debt model needs except the backstop buffer.
    """
    book = fetch_lend_borrow(timeout=timeout)
    out: List[Dict[str, Any]] = []
    for pool in fetch_pools(project=project, chain=chain, min_tvl_usd=min_tvl_usd, timeout=timeout):
        extra = book.get(pool["pool_id"])
        if extra is None:
            continue  # not a lending market
        merged = {**pool, **extra}
        if not merged.get("underlying_tokens"):
            merged["underlying_tokens"] = pool.get("underlying_tokens") or []
        out.append(merged)
    out.sort(key=lambda r: -r["tvl_usd"])
    return out


def fetch_protocol_meta(slug: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """DeFiLlama protocol record: TVL by chain, oracle breakdown, hack history."""
    payload = _get_json(PROTOCOL_URL.format(slug=slug), timeout=timeout)
    if not isinstance(payload, dict):
        return {}
    return {
        "slug": slug,
        "name": payload.get("name", slug),
        "category": payload.get("category", ""),
        "description": payload.get("description", ""),
        "chains": list(payload.get("chains", []) or []),
        "current_chain_tvls": dict(payload.get("currentChainTvls") or {}),
        "oracles_breakdown": payload.get("oraclesBreakdown") or {},
        "audits": payload.get("audits"),
        "audit_links": list(payload.get("audit_links") or []),
        "hacks": payload.get("hacks") or [],
        "methodology": payload.get("methodology"),
    }


# ---------------------------------------------------------------------------
# Graph builders
# ---------------------------------------------------------------------------


def build_graph_from_lending_markets(
    markets: Iterable[Dict[str, Any]],
    backstop_buffers: Optional[Dict[str, float]] = None,
    top_n: Optional[int] = None,
) -> DeFiContagionGraph:
    """Fold real lending markets into a contagion graph with solvency numbers.

    ``backstop_buffers`` optionally maps market name (or pool id) to a USD
    safety-module balance; live APIs do not publish these, so the default of
    zero makes ``uncovered_loss_usd`` an upper bound.

    Market node metadata written for :mod:`~blastradius.contagion.scoring`:
    ``token_supplied_usd`` (total supplied), ``debt_against_token_usd``
    (total borrowed), ``backstop_buffer_usd``, plus ``ltv`` / ``borrowable`` /
    ``debt_ceiling_usd`` as risk context.
    """
    buffers = backstop_buffers or {}
    graph = DeFiContagionGraph()
    seen: set = set()

    for i, m in enumerate(markets):
        if top_n is not None and i >= top_n:
            break
        project = m.get("project") or "unknown"
        chain = m.get("chain") or "unknown"
        symbol = m.get("symbol") or "UNKNOWN"
        pool_id = m.get("pool_id") or ""
        market_name = f"{project} {symbol} ({chain})"
        if market_name in seen:
            continue
        seen.add(market_name)

        supplied = float(m.get("total_supply_usd") or m.get("tvl_usd") or 0.0)
        borrowed = float(m.get("total_borrow_usd") or 0.0)
        buffer_usd = float(buffers.get(market_name) or buffers.get(pool_id) or 0.0)

        graph.add_node(
            NodeKind.MARKET,
            market_name,
            tvl_usd=float(m.get("tvl_usd") or supplied),
            meta={
                "pool_id": pool_id,
                "pool_meta": m.get("pool_meta") or "",
                "token_supplied_usd": supplied,
                "debt_against_token_usd": borrowed,
                "backstop_buffer_usd": buffer_usd,
                "ltv": m.get("ltv"),
                "borrowable": m.get("borrowable"),
                "borrow_factor": m.get("borrow_factor"),
                "debt_ceiling_usd": m.get("debt_ceiling_usd"),
                "minted_coin": m.get("minted_coin"),
                "underlying_tokens": list(m.get("underlying_tokens") or []),
                "source": "defillama:yields+lendBorrow",
            },
        )
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


def build_graph_from_pools(
    pools: Iterable[Dict[str, Any]],
    top_n: Optional[int] = None,
) -> DeFiContagionGraph:
    """Fold pool rows into a contagion graph — **exposure only**.

    Carries no borrow/backstop figures, so
    :func:`~blastradius.contagion.scoring.simulate_token_collapse` reports zero
    bad debt for these markets. Use
    :func:`build_graph_from_lending_markets` for solvency numbers.
    """
    graph = DeFiContagionGraph()
    seen: set = set()

    for i, pool in enumerate(pools):
        if top_n is not None and i >= top_n:
            break
        project = pool.get("project") or "unknown"
        chain = pool.get("chain") or "unknown"
        symbol = pool.get("symbol") or "UNKNOWN"
        tvl = float(pool.get("tvl_usd") or 0.0)
        market_name = f"{project} {symbol} ({chain})"
        if market_name in seen:
            continue
        seen.add(market_name)

        graph.add_node(
            NodeKind.MARKET,
            market_name,
            tvl_usd=tvl,
            meta={"pool_id": pool.get("pool_id") or "", "source": "defillama:yields"},
        )
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
          "tokens":  [{"name": "rsETH", "tvl_usd": 1.07e9, "wrapped_on": ["Base"]}],
          "markets": [{"id": "aave-v3-eth-pool", "name": "...", "protocol": "Aave",
                       "chain": "Ethereum", "tvl_usd": 5.2e9,
                       "token_supplied_usd": 2.92e8, "debt_against_token_usd": 2.4e8,
                       "backstop_buffer_usd": 6e7, "collateral": ["rsETH"]}]
        }

    Accepts a dict, or a path to a JSON file. Extra keys are preserved on node
    ``meta`` so downstream scoring can use them.
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
        meta.setdefault("source", "declared-whitelist")
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
