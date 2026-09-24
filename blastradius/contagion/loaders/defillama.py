"""DeFiLlama loader — live TVL figures, no API key required.

Deliberately stdlib-only (``urllib``) so it adds no dependency to the project.
Endpoints (public, read-only):

* ``GET https://api.llama.fi/protocols``      -> list of protocols + TVL
* ``GET https://api.llama.fi/tvl/{slug}``     -> single protocol TVL

Used to keep graph node ``tvl_usd`` current. This loader is **network code**;
tests never call it (see ``tests/test_contagion.py``).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

BASE_URL = "https://api.llama.fi"
USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 20.0


def _get(path: str, timeout: float = DEFAULT_TIMEOUT) -> Any:
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed host
        return json.loads(response.read().decode("utf-8"))


def fetch_protocols(timeout: float = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """All protocols with their current TVL, sorted descending."""
    payload = _get("/protocols", timeout=timeout)
    rows: List[Dict[str, Any]] = []
    for item in payload or []:
        rows.append(
            {
                "slug": item.get("slug") or item.get("name", "").lower(),
                "name": item.get("name", ""),
                "category": item.get("category", ""),
                "chain": item.get("chain", ""),
                "chains": item.get("chains", []) or [],
                "tvl_usd": float(item.get("tvl") or 0.0),
                "slug_url": f"https://defillama.com/protocol/{item.get('slug') or item.get('name', '').lower()}",
            }
        )
    rows.sort(key=lambda r: -r["tvl_usd"])
    return rows


def fetch_protocol_tvl(slug: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[float]:
    """Current TVL for one protocol slug, or ``None`` if unknown."""
    try:
        payload = _get(f"/tvl/{slug}", timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None
    if isinstance(payload, (int, float)):
        return float(payload)
    return None


def find_protocols(name: str, timeout: float = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """Case-insensitive substring search over DeFiLlama's protocol list."""
    needle = name.lower()
    return [p for p in fetch_protocols(timeout=timeout) if needle in p["name"].lower() or needle in p["slug"].lower()]
