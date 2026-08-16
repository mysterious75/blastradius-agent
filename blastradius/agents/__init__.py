"""BlastRadius multi-agent graph package.

Role-based agents (recon → exploit → patch) cooperate through a thread-safe
blackboard: candidates are discovered, proven in the sandbox (parallel), and
patched — with chain linking between related findings. Deterministic and
offline-testable; the LLM is never trusted to "confirm" anything.

Entry points:
    python -m blastradius.agents --target <url|path>
    from blastradius.agents.orchestrator import AgentGraph
"""

from blastradius.agents.blackboard import AgentEvent, Blackboard
from blastradius.agents.orchestrator import AgentGraph, AgentRunResult
from blastradius.agents.roles import ExploitAgent, PatchAgent, ReconAgent

__all__ = [
    "AgentEvent",
    "Blackboard",
    "AgentGraph",
    "AgentRunResult",
    "ReconAgent",
    "ExploitAgent",
    "PatchAgent",
]
