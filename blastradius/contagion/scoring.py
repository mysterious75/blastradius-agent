"""Blast-radius scoring and bad-debt simulation.

Two distinct questions, deliberately kept apart:

1. :func:`score_blast_radius` — *how far does the damage travel?*  A
   reachability + exposure score, decayed by hop count. Pre-deployment question.
2. :func:`simulate_token_collapse` — *if this token goes to zero, how much debt
   survives with no collateral behind it, and how much of that the protocol's
   own buffer can absorb?*  This is the exact mechanic that left Aave's WETH
   reserve carrying unliquidatable bad debt after the KelpDAO drain (18 Apr
   2026): the attacker borrowed against rsETH collateral whose backing had
   just been drained, so liquidators had nothing to seize.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .graph import BlastRadius, DeFiContagionGraph
from .schema import EdgeKind, NodeKind


@dataclass
class BlastRadiusScore:
    """Reachability / exposure score for a single seed asset."""

    seed_id: str
    node_count: int
    protocol_count: int
    chain_count: int
    market_count: int
    depth: int
    direct_exposure_usd: float
    reachable_tvl_usd: float
    decayed_tvl_usd: float
    severity: str  # INFO | LOW | MEDIUM | HIGH | CRITICAL

    def as_rows(self) -> List[List[str]]:
        return [
            ["Severity", self.severity],
            ["Affected nodes", str(self.node_count)],
            [
                "Markets / protocols / chains",
                f"{self.market_count} / {self.protocol_count} / {self.chain_count}",
            ],
            ["Graph depth", str(self.depth)],
            ["Direct exposure (USD)", f"{self.direct_exposure_usd:,.0f}"],
            ["Reachable TVL (USD)", f"{self.reachable_tvl_usd:,.0f}"],
            ["Decayed TVL (USD)", f"{self.decayed_tvl_usd:,.0f}"],
        ]


def _severity(decayed_tvl_usd: float) -> str:
    if decayed_tvl_usd >= 500_000_000:
        return "CRITICAL"
    if decayed_tvl_usd >= 100_000_000:
        return "HIGH"
    if decayed_tvl_usd >= 10_000_000:
        return "MEDIUM"
    if decayed_tvl_usd > 0:
        return "LOW"
    return "INFO"


def score_blast_radius(
    graph: DeFiContagionGraph,
    seed: str,
    max_depth: int = 5,
    hop_decay: float = 0.65,
) -> BlastRadiusScore:
    """Score how much value a failure at ``seed`` can touch.

    ``hop_decay`` shrinks TVL credited to distant nodes — a second-order
    dependency is real exposure but usually bites later and softer than direct
    collateral exposure.
    """
    radius: BlastRadius = graph.blast_radius(seed, max_depth=max_depth)

    direct = 0.0
    for edge in graph.backend.successors(seed, kind=EdgeKind.COLLATERAL_IN):
        market = graph.backend.node(edge.dst)
        if market is not None and market.kind is NodeKind.MARKET:
            direct += float(market.meta.get("token_supplied_usd", market.tvl_usd))

    decayed = sum(e.tvl_usd * (hop_decay ** e.hop) for e in radius.entries)

    return BlastRadiusScore(
        seed_id=seed,
        node_count=radius.node_count,
        protocol_count=len(radius.names_of_kind(NodeKind.PROTOCOL)),
        chain_count=len(radius.names_of_kind(NodeKind.CHAIN)),
        market_count=len(radius.names_of_kind(NodeKind.MARKET)),
        depth=radius.depth,
        direct_exposure_usd=direct,
        reachable_tvl_usd=radius.total_tvl_usd,
        decayed_tvl_usd=decayed,
        severity=_severity(decayed),
    )


@dataclass
class BadDebtRow:
    """One lending market's solvency outcome under a token collapse.

    ``collateral_at_risk_usd`` is collateral *denominated in* the failing token
    and ``debt_against_token_usd`` is what was borrowed against it. When the
    token goes to zero the collateral disappears but the debt does not, and
    liquidators cannot liquidate a position with nothing to seize.
    """

    market_id: str
    market_name: str
    protocol: str
    collateral_at_risk_usd: float
    debt_against_token_usd: float
    backstop_buffer_usd: float
    bad_debt_usd: float
    uncovered_loss_usd: float
    liquidatable: bool  # False -> liquidation cannot clear it

    @property
    def outcome(self) -> str:
        return "SOLVENT" if self.liquidatable else "UNLIQUIDATABLE"


def simulate_token_collapse(
    graph: DeFiContagionGraph,
    seed: str,
    price_ratio: float = 0.0,
) -> List[BadDebtRow]:
    """Project bad debt across lending markets if ``seed``'s price collapses.

    Per market listing ``seed`` as collateral::

        bad_debt     = debt_against_token * (1 - price_ratio)
        uncovered    = max(0, bad_debt - backstop_buffer)
        liquidatable = bad_debt <= 0

    ``uncovered_loss_usd`` is what the pool's own reserves must eat once the
    safety module / umbrella backstop is exhausted — the Aave WETH outcome in
    the KelpDAO case.
    """
    if not 0.0 <= price_ratio <= 1.0:
        raise ValueError("price_ratio must be between 0.0 and 1.0")

    rows: List[BadDebtRow] = []
    for edge in graph.backend.successors(seed, kind=EdgeKind.COLLATERAL_IN):
        market = graph.backend.node(edge.dst)
        if market is None or market.kind is not NodeKind.MARKET:
            continue

        at_risk = float(market.meta.get("token_supplied_usd", market.tvl_usd))
        debt = float(market.meta.get("debt_against_token_usd", 0.0))
        buffer = float(market.meta.get("backstop_buffer_usd", 0.0))

        bad_debt = debt * (1.0 - price_ratio)
        uncovered = max(0.0, bad_debt - buffer)

        proto_name = ""
        for hosted in graph.backend.successors(market.id, kind=EdgeKind.PART_OF):
            proto = graph.backend.node(hosted.dst)
            if proto is not None:
                proto_name = proto.name
                break

        rows.append(
            BadDebtRow(
                market_id=market.id,
                market_name=market.name,
                protocol=proto_name,
                collateral_at_risk_usd=at_risk,
                debt_against_token_usd=debt,
                backstop_buffer_usd=buffer,
                bad_debt_usd=bad_debt,
                uncovered_loss_usd=uncovered,
                liquidatable=bad_debt <= 0.0,
            )
        )

    return sorted(rows, key=lambda r: (-r.uncovered_loss_usd, r.market_name))
