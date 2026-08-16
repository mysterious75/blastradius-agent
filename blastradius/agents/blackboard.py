"""Blackboard — shared, thread-safe context for the agent graph.

Every agent posts structured events (candidates, confirmations, patches,
chain notes) to the blackboard; the orchestrator and the report read from it.
This is the "shared memory" that lets specialized agents cooperate without
coupling: ReconAgent discovers, ExploitAgent proves (in parallel), PatchAgent
fixes — each only ever talks to the blackboard.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AgentEvent:
    """One event posted by an agent."""

    agent: str  # recon | exploit | patch | orchestrator
    kind: str  # candidate | confirmed | rejected | patch | chain | note
    payload: Dict[str, Any]
    at: float = field(default_factory=time.time)


class Blackboard:
    """Thread-safe event + artifact store shared by all agents."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events: List[AgentEvent] = []
        self._chains: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Posting
    # ------------------------------------------------------------------

    def post(self, agent: str, kind: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._events.append(AgentEvent(agent=agent, kind=kind, payload=payload))

    def add_chain(self, chain: Dict[str, Any]) -> None:
        """Register a discovered dependency between findings."""
        with self._lock:
            self._chains.append(chain)
            self._events.append(AgentEvent(agent="exploit", kind="chain", payload=chain))

    # ------------------------------------------------------------------
    # Reads (aggregations)
    # ------------------------------------------------------------------

    def of_kind(self, kind: str) -> List[AgentEvent]:
        with self._lock:
            return [e for e in self._events if e.kind == kind]

    def candidates(self) -> List[AgentEvent]:
        return self.of_kind("candidate")

    def confirmed(self) -> List[AgentEvent]:
        return self.of_kind("confirmed")

    def rejected(self) -> List[AgentEvent]:
        return self.of_kind("rejected")

    def patches(self) -> List[AgentEvent]:
        return self.of_kind("patch")

    def chains(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._chains)

    def events(self) -> List[AgentEvent]:
        with self._lock:
            return list(self._events)

    def summary(self) -> Dict[str, int]:
        """Counts per event kind — for the agent-graph report."""
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.kind] = counts.get(e.kind, 0) + 1
        return counts
