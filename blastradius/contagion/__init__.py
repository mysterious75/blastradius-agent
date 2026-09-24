"""BlastRadius contagion graph — DeFi composability blast radius (Phase 6).

Pre-deployment contagion scoring + security-configuration audit:

* *if this token fails, how much TVL across which protocols and chains goes
  with it?*  (:mod:`~blastradius.contagion.graph`, :mod:`~blastradius.contagion.scoring`)
* *is this cross-chain / protocol config redundant enough to survive one
  compromised signer?*  (:mod:`~blastradius.contagion.config_audit`)

Complements :mod:`blastradius.blast_radius` (supply-chain ``Package -> Repo``)
with the on-chain equivalent, ``Token -> Market -> Protocol -> Chain``.
"""

from .config_audit import AuditReport, ConfigAuditor, Finding
from .graph import BlastRadius, BlastRadiusEntry, DeFiContagionGraph, MemoryBackend
from .schema import Edge, EdgeKind, Node, NodeKind
from .scoring import BadDebtRow, BlastRadiusScore, score_blast_radius, simulate_token_collapse

__all__ = [
    "AuditReport",
    "BadDebtRow",
    "BlastRadius",
    "BlastRadiusEntry",
    "BlastRadiusScore",
    "ConfigAuditor",
    "DeFiContagionGraph",
    "Edge",
    "EdgeKind",
    "Finding",
    "MemoryBackend",
    "Node",
    "NodeKind",
    "score_blast_radius",
    "simulate_token_collapse",
]
