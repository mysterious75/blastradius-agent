"""DeFi contagion domain model.

Edges point in the direction **damage travels**: if ``src`` breaks, ``dst`` is
damaged. This matches the convention already used by
:mod:`blastradius.blast_radius` (``(Package)-[:USED_IN]->(Repo)``), so blast
radius is a forward traversal over ``successors()``.

That is exactly how the KelpDAO / LayerZero DVN incident (18 Apr 2026)
cascaded in the wild: a token's backing broke -> markets holding it as
collateral -> the protocols hosting those markets -> every chain they ran on.
See ``data/seed_kelpdao_case.json``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class NodeKind(str, Enum):
    """Entity types tracked in the contagion graph."""

    TOKEN = "Token"
    MARKET = "Market"
    PROTOCOL = "Protocol"
    CHAIN = "Chain"
    ORACLE = "Oracle"


class EdgeKind(str, Enum):
    """Impact relations. If ``src`` breaks, ``dst`` is damaged."""

    COLLATERAL_IN = "COLLATERAL_IN"  # (Token)    -> (Market)   collateral listing
    PART_OF = "PART_OF"  # (Market)   -> (Protocol) market insolvency hits the protocol
    DEPLOYED_ON = "DEPLOYED_ON"  # (Protocol) -> (Chain)    ecosystem exposure
    WRAPPED_ON = "WRAPPED_ON"  # (Token)    -> (Chain)    cross-chain copy loses backing
    BACKS = "BACKS"  # (Token)    -> (Token)    LRT / LST nesting
    PRICES = "PRICES"  # (Oracle)   -> (Market)   feed failure misprices the market


@dataclass
class Node:
    """A graph node carrying an optional USD exposure figure."""

    id: str
    kind: NodeKind
    name: str
    tvl_usd: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make_id(kind: NodeKind, name: str) -> str:
        return f"{kind.value}:{name}"


@dataclass
class Edge:
    """An impact edge: if ``src`` breaks, ``dst`` is damaged."""

    src: str
    dst: str
    kind: EdgeKind
    weight: float = 1.0
    meta: Dict[str, Any] = field(default_factory=dict)
