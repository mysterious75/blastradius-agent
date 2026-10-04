"""Backstop reader — on-chain Safety Module / Umbrella balances via public RPC.

Fills the ``backstop_buffer_usd`` gap that live DeFiLlama data cannot provide
(see ``loaders/collateral.py``: markets built from free APIs carry
``backstop_buffer_usd = 0``, making ``uncovered_loss_usd`` an upper bound).

Reads, per entry in ``data/backstop_sources.json``:

* ``erc20-totalSupply`` — ``totalSupply()`` of a stake token (e.g. legacy
  stkAAVE) × USD price;
* ``erc4626-totalAssets`` — ``totalAssets()`` of an Umbrella StakeToken vault
  (staked underlying, slashable per deficit).

Prices come from on-chain Chainlink USD feeds (``latestAnswer()``); no API
key anywhere. RPC via keyless public endpoints with fallback across the
configured list. All network code is isolated in ``fetch_*``; builders take
plain dicts so tests stay offline.

Never hardcode an unverified stake-token address: Umbrella StakeToken
deployments belong in ``data/backstop_sources.json``, filled by the operator
from verified deployments only.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 20.0
MIN_REQUEST_INTERVAL_S = 0.3

_last_request_at = 0.0

# Canonical function selectors.
_SEL_TOTAL_SUPPLY = "18160ddd"
_SEL_TOTAL_ASSETS = "01e1d114"
_SEL_BALANCE_OF = "70a08231"
_SEL_DECIMALS = "313ce567"
_SEL_LATEST_ROUND_DATA = "feaf968c"


def _default_sources_path() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "backstop_sources.json"


def load_sources(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read ``data/backstop_sources.json`` ({} when absent)."""
    candidate = Path(path) if path else _default_sources_path()
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def validate_backstop_sources(sources: Optional[Dict[str, Any]] = None) -> List[str]:
    """Validate operator-supplied backstop configuration without network use.

    Umbrella activation starts on Ethereum; a non-Ethereum source is only
    accepted with explicit ``verified_by`` provenance naming the verified
    deployment reference. This prevents guessing cross-chain addresses while
    keeping the reader ready for verified future deployments.
    """
    cfg = sources if sources is not None else load_sources()
    errors: List[str] = []
    rpcs_by_chain = cfg.get("rpcs", {}) or {}
    for entry in cfg.get("sources", []) or []:
        entry_id = str(entry.get("id", "<missing id>"))
        if not entry.get("address"):
            errors.append(f"{entry_id}: missing contract address")
        if entry.get("kind") not in ("erc20-totalSupply", "erc4626-totalAssets"):
            errors.append(f"{entry_id}: unknown backstop kind {entry.get('kind')!r}")
        chain = str(entry.get("chain", "1"))
        if not rpcs_by_chain.get(chain):
            errors.append(f"{entry_id}: no RPC configured for chain {chain}")
        if chain != "1" and not entry.get("verified_by"):
            errors.append(f"{entry_id}: non-Ethereum backstop requires verified_by provenance")
    return errors


def _rpc_call(rpc: str, to_addr: str, data: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    global _last_request_at
    wait = MIN_REQUEST_INTERVAL_S - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": to_addr, "data": "0x" + data}, "latest"],
        }
    ).encode()
    request = urllib.request.Request(
        rpc, data=body, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - public RPC
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        _last_request_at = time.monotonic()
    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeError(f"rpc error: {json.dumps(payload['error'])[:120]}")
    return str(payload.get("result", "0x0"))


def _call_first(rpcs: List[str], to_addr: str, data: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    errors = []
    for rpc in rpcs:
        try:
            return _rpc_call(rpc, to_addr, data, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - try next RPC endpoint
            errors.append(f"{rpc}: {exc}")
    raise RuntimeError("all RPCs failed: " + " | ".join(errors)[:300])


def _to_int(hexdata: str) -> int:
    try:
        return int(hexdata, 16)
    except (TypeError, ValueError):
        return 0


def read_total_supply(rpcs: List[str], token: str, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Raw ``totalSupply()`` of an ERC-20 stake token."""
    return _to_int(_call_first(rpcs, token, _SEL_TOTAL_SUPPLY, timeout=timeout))


def read_total_assets(rpcs: List[str], vault: str, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Raw ``totalAssets()`` of an ERC-4626 StakeToken vault."""
    return _to_int(_call_first(rpcs, vault, _SEL_TOTAL_ASSETS, timeout=timeout))


def read_chainlink_usd(
    rpcs: List[str], feed: str, timeout: float = DEFAULT_TIMEOUT
) -> Optional[float]:
    """USD price from a Chainlink feed (``latestRoundData()`` answer, 8 decimals)."""
    raw_hex = _call_first(rpcs, feed, _SEL_LATEST_ROUND_DATA, timeout=timeout)
    try:
        answer = int(raw_hex[66:130], 16)
    except (TypeError, ValueError):
        return None
    if answer <= 0:
        return None
    return answer / 1e8


def fetch_backstops(
    sources: Optional[Dict[str, Any]] = None, timeout: float = DEFAULT_TIMEOUT
) -> Dict[str, float]:
    """Read every configured source; returns ``{source_id: buffer_usd}``.

    Slashable fraction applied: ``slashable_pct`` (default 100) models the
    maximum governance/contract slash (e.g. stkAAVE 20%).
    """
    cfg = sources if sources is not None else load_sources()
    rpcs_by_chain = cfg.get("rpcs", {}) or {}
    feeds = cfg.get("chainlink_usd_feeds", {}) or {}
    out: Dict[str, float] = {}
    for entry in cfg.get("sources", []) or []:
        try:
            out[entry["id"]] = _read_entry(entry, rpcs_by_chain, feeds, timeout)
        except Exception:
            continue  # best-effort per source; never fail the whole batch
    return out


def _read_entry(
    entry: Dict[str, Any], rpcs_by_chain: Dict[str, Any], feeds: Dict[str, Any], timeout: float
) -> float:
    chain = str(entry.get("chain", "1"))
    rpcs = list(rpcs_by_chain.get(chain) or rpcs_by_chain.get(1) or [])
    if not rpcs:
        raise RuntimeError("no RPC configured")
    kind = entry.get("kind", "")
    if kind == "erc20-totalSupply":
        raw = read_total_supply(rpcs, entry["address"], timeout=timeout)
    elif kind == "erc4626-totalAssets":
        raw = read_total_assets(rpcs, entry["address"], timeout=timeout)
    else:
        raise RuntimeError(f"unknown kind {kind!r}")
    decimals = int(entry.get("decimals", 18))
    amount = raw / (10**decimals)
    feed_key = entry.get("price_usd_feed", "")
    feed = feeds.get(feed_key, "")
    price = read_chainlink_usd(rpcs, feed, timeout=timeout) if feed else None
    if price is None:
        price = (
            1.0
            if str(entry.get("underlying", "")).upper() in ("USDC", "USDT", "DAI", "GHO")
            else 0.0
        )
    slashable = float(entry.get("slashable_pct", 100)) / 100.0
    return amount * price * slashable
