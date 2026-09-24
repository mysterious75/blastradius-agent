"""DeFi contagion graph — dependency blast radius for on-chain assets.

Same shape as :mod:`blastradius.blast_radius.graph` (memory backend, facade
class, JSON snapshots) applied to the DeFi domain. Instead of
``Package -> Repo`` we model ``Token -> Market -> Protocol -> Chain``.

Edges run **in the direction damage travels** (``src`` breaks -> ``dst``
damaged), matching ``blast_radius.graph``'s ``(Package)-[:USED_IN]->(Repo)``.
So the blast radius of a broken node is everything reachable over
:meth:`MemoryBackend.successors`.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from .schema import Edge, EdgeKind, Node, NodeKind

Seed = Union[str, Tuple[NodeKind, str]]


class MemoryBackend:
    """In-memory contagion graph (dict-based, no database required)."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.out_edges: Dict[str, List[Edge]] = {}
        self.in_edges: Dict[str, List[Edge]] = {}

    # -- writes ------------------------------------------------------------
    def add_node(self, node: Node) -> None:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return
        # Merge: keep the larger TVL; existing metadata keys win.
        existing.tvl_usd = max(existing.tvl_usd, node.tvl_usd)
        merged = dict(node.meta)
        merged.update(existing.meta)
        existing.meta = merged

    def add_edge(self, edge: Edge) -> None:
        self.out_edges.setdefault(edge.src, []).append(edge)
        self.in_edges.setdefault(edge.dst, []).append(edge)

    # -- reads -------------------------------------------------------------
    def node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def successors(self, node_id: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        """Nodes damaged when ``node_id`` breaks (impact flows outward)."""
        edges = self.out_edges.get(node_id, [])
        return [e for e in edges if kind is None or e.kind == kind]

    def predecessors(self, node_id: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        """Nodes whose failure would damage ``node_id`` (dependency lookup)."""
        edges = self.in_edges.get(node_id, [])
        return [e for e in edges if kind is None or e.kind == kind]

    def all_nodes(self) -> List[Node]:
        return list(self.nodes.values())

    def all_edges(self) -> List[Edge]:
        out: List[Edge] = []
        for edges in self.out_edges.values():
            out.extend(edges)
        return out


@dataclass
class BlastRadiusEntry:
    """One affected node inside a blast-radius result."""

    node_id: str
    kind: NodeKind
    name: str
    hop: int
    tvl_usd: float
    via: str  # edge kind that carried the damage here
    path: Tuple[str, ...]


@dataclass
class BlastRadius:
    """Result of a blast-radius traversal."""

    seed_id: str
    entries: List[BlastRadiusEntry] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.entries)

    @property
    def depth(self) -> int:
        return max((e.hop for e in self.entries), default=0)

    @property
    def total_tvl_usd(self) -> float:
        """Sum of TVL across affected nodes (deduplicated by node id)."""
        seen: Set[str] = set()
        total = 0.0
        for e in self.entries:
            if e.node_id in seen:
                continue
            seen.add(e.node_id)
            total += e.tvl_usd
        return total

    def of_kind(self, kind: NodeKind) -> List[BlastRadiusEntry]:
        return [e for e in self.entries if e.kind == kind]

    def names_of_kind(self, kind: NodeKind) -> List[str]:
        return sorted({e.name for e in self.entries if e.kind == kind})

    def rows(self) -> List[List[str]]:
        return [
            [str(e.hop), e.kind.value, e.name, f"{e.tvl_usd:,.0f}", e.via]
            for e in sorted(self.entries, key=lambda e: (e.hop, -e.tvl_usd))
        ]


class DeFiContagionGraph:
    """``Token -> Market -> Protocol -> Chain`` contagion graph.

    Edges run in the direction damage travels; :meth:`blast_radius` walks the
    graph forward to collect everything a failure at ``seed`` would take out.
    """

    def __init__(self, backend: Optional[MemoryBackend] = None) -> None:
        self.backend = backend or MemoryBackend()

    # -- writes ------------------------------------------------------------
    def add_node(
        self,
        kind: NodeKind,
        name: str,
        tvl_usd: float = 0.0,
        meta: Optional[dict] = None,
        node_id: Optional[str] = None,
    ) -> Node:
        """Add (or merge into) a node. ``node_id`` overrides the derived
        ``"<Kind>:<name>"`` id so snapshots can use stable slugs."""
        node = Node(
            node_id or Node.make_id(kind, name), kind, name, tvl_usd, dict(meta or {})
        )
        self.backend.add_node(node)
        return node

    def add_edge(
        self,
        kind: EdgeKind,
        src: Tuple[NodeKind, str],
        dst: Tuple[NodeKind, str],
        weight: float = 1.0,
        meta: Optional[dict] = None,
    ) -> Edge:
        edge = Edge(Node.make_id(*src), Node.make_id(*dst), kind, weight, dict(meta or {}))
        self.backend.add_edge(edge)
        return edge

    # -- reads -------------------------------------------------------------
    @staticmethod
    def seed_id(kind: NodeKind, name: str) -> str:
        return Node.make_id(kind, name)

    def blast_radius(
        self,
        seed: Seed,
        max_depth: int = 5,
        kinds: Optional[Sequence[NodeKind]] = None,
    ) -> BlastRadius:
        """Everything damaged if ``seed`` fails, transitively.

        ``kinds`` optionally restricts which node kinds are *returned* — the
        traversal itself is unfiltered so hops and reachability stay honest.
        """
        seed_id = seed if isinstance(seed, str) else Node.make_id(*seed)
        allow = set(kinds) if kinds else None

        seen: Set[str] = {seed_id}
        queue: deque[Tuple[str, int, Tuple[str, ...]]] = deque([(seed_id, 0, (seed_id,))])
        entries: List[BlastRadiusEntry] = []

        while queue:
            current, hop, path = queue.popleft()
            if hop >= max_depth:
                continue
            for edge in self.backend.successors(current):
                affected = edge.dst
                if affected in seen:
                    continue
                seen.add(affected)
                node = self.backend.node(affected)
                if node is None:
                    continue
                new_path = path + (affected,)
                if allow is None or node.kind in allow:
                    entries.append(
                        BlastRadiusEntry(
                            node_id=affected,
                            kind=node.kind,
                            name=node.name,
                            hop=hop + 1,
                            tvl_usd=node.tvl_usd,
                            via=edge.kind.value,
                            path=new_path,
                        )
                    )
                queue.append((affected, hop + 1, new_path))

        return BlastRadius(seed_id=seed_id, entries=entries)

    def impacted_chains(self, seed: Seed, max_depth: int = 5) -> List[str]:
        """Chains touched by a failure at ``seed`` (including wrapped copies)."""
        radius = self.blast_radius(seed, max_depth=max_depth)
        chains = set(radius.names_of_kind(NodeKind.CHAIN))
        seed_id = seed if isinstance(seed, str) else Node.make_id(*seed)
        for edge in self.backend.successors(seed_id, kind=EdgeKind.WRAPPED_ON):
            node = self.backend.node(edge.dst)
            if node is not None:
                chains.add(node.name)
        return sorted(chains)

    # -- persistence -------------------------------------------------------
    @classmethod
    def from_json(cls, path: Union[str, Path]) -> "DeFiContagionGraph":
        """Load a graph snapshot written by :meth:`to_json` or hand-authored."""
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, payload: dict) -> "DeFiContagionGraph":
        """Build a graph from a snapshot dict.

        Ids are taken verbatim from ``id`` / ``src`` / ``dst`` so that snapshots
        may use stable slugs (``Market:aave-v3-eth-pool``) whose display names
        differ from the id (``Aave V3 Ethereum pool (rsETH listing)``).
        """
        graph = cls()
        for raw in payload.get("nodes", []):
            kind = NodeKind(raw["kind"])
            name = raw.get("name") or raw.get("id", "").split(":", 1)[-1]
            node_id = raw.get("id") or Node.make_id(kind, name)
            graph.backend.add_node(
                Node(
                    id=node_id,
                    kind=kind,
                    name=name,
                    tvl_usd=float(raw.get("tvl_usd", 0.0)),
                    meta=dict(raw.get("meta", {})),
                )
            )
        for raw in payload.get("edges", []):
            graph.backend.add_edge(
                Edge(
                    src=raw["src"],
                    dst=raw["dst"],
                    kind=EdgeKind(raw["kind"]),
                    weight=float(raw.get("weight", 1.0)),
                    meta=dict(raw.get("meta", {})),
                )
            )
        return graph

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind.value,
                    "name": n.name,
                    "tvl_usd": n.tvl_usd,
                    "meta": n.meta,
                }
                for n in sorted(self.backend.all_nodes(), key=lambda n: n.id)
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "kind": e.kind.value,
                    "weight": e.weight,
                    "meta": e.meta,
                }
                for e in sorted(
                    self.backend.all_edges(), key=lambda e: (e.src, e.dst, e.kind.value)
                )
            ],
        }

    def to_json(self, path: Union[str, Path]) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
