"""AgentGraph — multi-agent orchestration with a shared blackboard.

Runs the specialized agent roles as a graph:

    ReconAgent (discover candidates)
      └─> ExploitAgent xN (prove in parallel, link chains)
            └─> PatchAgent (generate + verify fixes)

Every stage communicates through the Blackboard (thread-safe event store), so
agents are decoupled and the whole run is auditable from the event log. The
graph is deterministic and LLM-free by default: the tools prove, nothing is
asserted. Each role carries a persona prompt (see roles.PERSONAS) so an LLM
reasoning layer can be added without changing the data flow.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from blastradius.agents.blackboard import AgentEvent, Blackboard
from blastradius.agents.roles import ExploitAgent, PatchAgent, ReconAgent
from blastradius.hunter.scanner import CVEHunter
from blastradius.patcher.loop import PatchLoop
from blastradius.security.input_validator import validate_github_url, validate_repo_path


@dataclass
class AgentRunResult:
    """Outcome of a multi-agent graph run."""

    target: str
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    confirmed: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[Dict[str, Any]] = field(default_factory=list)
    patches: List[Dict[str, Any]] = field(default_factory=list)
    chains: List[Dict[str, Any]] = field(default_factory=list)
    events: List[AgentEvent] = field(default_factory=list)
    files_scanned: int = 0
    elapsed_seconds: float = 0.0
    agents: List[str] = field(default_factory=list)


class AgentGraph:
    """Coordinate recon → exploit → patch agents over one target."""

    def __init__(
        self,
        hunter: Optional[CVEHunter] = None,
        patch_loop: Optional[PatchLoop] = None,
        exploit_workers: int = 4,
        min_confidence: float = 0.7,
    ):
        self.recon = ReconAgent(hunter=hunter, min_confidence=min_confidence)
        self.exploit = ExploitAgent(max_workers=exploit_workers)
        self.patch = PatchAgent(patch_loop=patch_loop)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str) -> AgentRunResult:
        """Run the full agent graph against a GitHub URL or local path."""
        started = time.time()
        repo_path, _ = self._acquire(target)
        blackboard = Blackboard()

        self.recon.run(blackboard, repo_path)
        self.exploit.run(blackboard)
        self.patch.run(blackboard)

        result = AgentRunResult(
            target=target,
            candidates=[e.payload for e in blackboard.candidates()],
            confirmed=[e.payload for e in blackboard.confirmed()],
            rejected=[e.payload for e in blackboard.rejected()],
            patches=[e.payload for e in blackboard.patches()],
            chains=blackboard.chains(),
            events=blackboard.events(),
            files_scanned=self.recon.hunter.files_scanned,
            elapsed_seconds=round(time.time() - started, 2),
            agents=[self.recon.name, self.exploit.name, self.patch.name],
        )
        result.candidates = self._drop_duplicates(result.candidates)
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _acquire(self, target: str) -> Tuple[str, str]:
        if target.startswith(("http://", "https://")):
            url = validate_github_url(target)
            return self.recon.hunter.clone_repo(url), url.rstrip("/").split("/")[-1]
        return validate_repo_path(target), Path(target).name or "unknown"

    @staticmethod
    def _drop_duplicates(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen, unique = set(), []
        for row in rows:
            key = (row.get("file"), row.get("line"), row.get("vuln_type"))
            if key not in seen:
                seen.add(key)
                unique.append(row)
        return unique
