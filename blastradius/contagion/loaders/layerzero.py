"""LayerZero wiring — DVN registry + Scan API pathways into the config auditor.

Two offline-safe pieces plus one live fetcher:

* :func:`load_dvn_registry` — fold the downloaded LayerZero metadata snapshot
  (``data/ingest/layerzero_metadata.json``) into ``{address: operator}`` so
  findings can name operators instead of raw addresses.
* :func:`build_pathways_from_messages` — convert Scan API message objects
  (``message.config.inboundConfig/outboundConfig`` + ``message.pathway``) into
  the auditor's ``pathways[]`` shape. Pure function, fully unit-testable.
* :func:`fetch_message` — live ``GET /v1/messages/tx/{hash}`` lookup
  (keyless, rate-limited). Network code, never called by tests.

Field shapes below were mapped live against the Scan API (see
``scripts/probe_lzmsg2.py``), not guessed: ``inboundConfig``/``outboundConfig``
carry ``confirmations, requiredDVNCount, optionalDVNCount,
optionalDVNThreshold, requiredDVNs[], requiredDVNNames[], optionalDVNs[],
optionalDVNNames[]``; ``pathway`` carries ``srcEid/dstEid/sender/receiver/id``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

SCAN_BASE = "https://scan.layerzero-api.com"
USER_AGENT = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
DEFAULT_TIMEOUT = 30.0
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
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed host
            return json.loads(response.read().decode("utf-8"))
    finally:
        _last_request_at = time.monotonic()


def fetch_message(tx_hash_or_guid: str, timeout: float = DEFAULT_TIMEOUT) -> List[Dict[str, Any]]:
    """Live Scan API lookup by tx hash (or guid). Returns message objects."""
    payload = _get_json(f"{SCAN_BASE}/v1/messages/tx/{tx_hash_or_guid}", timeout=timeout)
    data = (payload or {}).get("data") or []
    return data if isinstance(data, list) else [data]


def load_dvn_registry(metadata: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """Fold a metadata snapshot into ``{lowercase_address: {operator, id}}``.

    Accepts the ``layerzero_metadata.json`` shape: top-level per-chain entries
    each with a ``dvns`` dict of ``address -> {canonicalName, id}``.
    """
    out: Dict[str, Dict[str, str]] = {}
    for chain in (metadata or {}).values():
        if not isinstance(chain, dict):
            continue
        for addr, info in (chain.get("dvns") or {}).items():
            if not isinstance(info, dict):
                continue
            out[str(addr).lower()] = {
                "operator": str(info.get("canonicalName") or ""),
                "id": str(info.get("id") or ""),
            }
    return out


def _norm_addrs(items: Any) -> List[str]:
    out = []
    for x in items or []:
        s = str(x or "").strip()
        if s:
            out.append(s)
    return out


def _config_to_pathway(
    cfg: Dict[str, Any],
    direction: str,
    pathway: Dict[str, Any],
    registry: Optional[Dict[str, Dict[str, str]]] = None,
    library: str = "",
) -> Dict[str, Any]:
    """One ULN config block -> one auditor pathway dict."""
    req = _norm_addrs(cfg.get("requiredDVNs"))
    opt = _norm_addrs(cfg.get("optionalDVNs"))
    entry: Dict[str, Any] = {
        "id": f"{pathway.get('id', 'pathway')}:{direction}",
        "chain": str((pathway.get("receiver") or {}).get("chain", "") or ""),
        "endpoint": "",
        "receive_library": str(library or ""),
        "confirmations": cfg.get("confirmations", 0),
        "required_dvn_count": cfg.get("requiredDVNCount", len(req)),
        "optional_dvn_count": cfg.get("optionalDVNCount", len(opt)),
        "optional_dvn_threshold": cfg.get("optionalDVNThreshold", 0),
        "required_dvns": req,
        "optional_dvns": opt,
        "required_dvn_operators": [
            (registry or {}).get(a.lower(), {}).get("operator", "") for a in req
        ],
        "optional_dvn_operators": [
            (registry or {}).get(a.lower(), {}).get("operator", "") for a in opt
        ],
        "source": "layerzero-scan",
    }
    return entry


def build_pathways_from_messages(
    messages: List[Dict[str, Any]],
    registry: Optional[Dict[str, Dict[str, str]]] = None,
) -> List[Dict[str, Any]]:
    """Convert Scan API messages into auditor ``pathways[]``.

    Each message yields up to two pathways (``outbound`` from
    ``outboundConfig``, ``inbound`` from ``inboundConfig``). Pure function.
    """
    out: List[Dict[str, Any]] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        cfg = msg.get("config") or {}
        pathway = msg.get("pathway") or {}
        for direction, key, lib_key in (
            ("outbound", "outboundConfig", "sendLibrary"),
            ("inbound", "inboundConfig", "receiveLibrary"),
        ):
            block = cfg.get(key) or {}
            if not block:
                continue
            out.append(
                _config_to_pathway(
                    block, direction, pathway, registry, library=str(cfg.get(lib_key, "") or "")
                )
            )
    return out


def build_audit_snapshot(
    messages: List[Dict[str, Any]],
    registry: Optional[Dict[str, Dict[str, str]]] = None,
    target: str = "layerzero-scan",
    executor: str = "",
    executor_operator: str = "",
) -> Dict[str, Any]:
    """Build a full auditor input dict from Scan messages.

    ``executor``/``executor_operator`` are attached to every pathway when
    known (the Scan message shape does not carry them; supply from the
    pathway docs or on-chain config).
    """
    pathways = build_pathways_from_messages(messages, registry)
    if executor or executor_operator:
        for p in pathways:
            p["executor"] = executor
            p["executor_operator"] = executor_operator
    return {"target": target, "pathways": pathways}
