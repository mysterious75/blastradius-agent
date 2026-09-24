"""BlastRadius contagion graph — DeFi composability blast radius (Phase 6).

Pre-deployment contagion scoring: *if this token fails, how much TVL across
which protocols and chains goes with it?*  Complements
:mod:`blastradius.blast_radius` (supply-chain Package -> Repo) with the
on-chain equivalent, ``Token -> Market -> Protocol -> Chain``.
"""

from .graph import BlastRadius, BlastRadiusEntry, DeFiContagionGraph, MemoryBackend
from .schema import Edge, EdgeKind, Node, NodeKind
from .scoring import BadDebtRow, BlastRadiusScore, score_blast_radius, simulate_token_collapse

__all__ = [
    "BadDebtRow",
    "BlastRadius",
    "BlastRadiusEntry",
    "BlastRadiusScore",
    "DeFiContagionGraph",
    "Edge",
    "EdgeKind",
    "MemoryBackend",
    "Node",
    "NodeKind",
    "score_blast_radius",
    "simulate_token_collapse",
]
