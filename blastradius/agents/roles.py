"""Specialized agent roles for the BlastRadius agent graph.

Each role owns one stage of the pentest and communicates only through the
blackboard. Decision logic is deterministic (the tools prove things — the
LLM is not trusted to "confirm"); every role also carries a persona prompt so
an LLM reasoning layer can be added later without changing the data flow.

    ReconAgent   — discover attack surface: scan repo, post candidates
    ExploitAgent — prove exploitability in the sandbox (parallel), link chains
    PatchAgent   — generate + verify patches for confirmed findings
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from blastradius.agents.blackboard import Blackboard
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.patcher.loop import PatchLoop
from blastradius.tools.sandbox_tool import run_exploit_sandbox

PERSONAS = {
    "recon": (
        "You are the RECON agent. Your job is attack-surface discovery: scan the "
        "target codebase, identify candidate vulnerability locations, and post them "
        "to the blackboard. Do not claim anything is exploitable — candidates only."
    ),
    "exploit": (
        "You are the EXPLOIT agent. Your job is proof: run each candidate's PoC in "
        "the sandbox and only post findings with an execution marker. Never assert — "
        "prove. Link findings that share a file into chains."
    ),
    "patch": (
        "You are the PATCH agent. Your job is remediation: generate a patch for every "
        "confirmed finding and verify it with all three checks (syntax, exploit "
        "re-run, regression tests). Flag anything uncertain for human review."
    ),
}


def _finding_dict(f: Finding) -> Dict[str, Any]:
    return {
        "file": f.file,
        "line": f.line,
        "vuln_type": f.vuln_type,
        "severity": f.severity,
        "cwe": f.cwe,
        "confidence": f.confidence,
        "payload": f.payload,
        "evidence": f.evidence,
        "remediation": f.remediation,
    }


class ReconAgent:
    """Discovers attack surface and posts candidates to the blackboard."""

    name = "recon"
    persona = PERSONAS["recon"]

    def __init__(self, hunter: Optional[CVEHunter] = None, min_confidence: float = 0.7):
        self.hunter = hunter or CVEHunter(min_confidence=min_confidence)

    def run(self, blackboard: Blackboard, repo_path: str) -> int:
        findings = self.hunter.scan_repo(repo_path)
        for finding in findings:
            blackboard.post(
                agent=self.name,
                kind="candidate",
                payload={**_finding_dict(finding), "files_scanned": self.hunter.files_scanned},
            )
        return len(findings)


class ExploitAgent:
    """Proves exploitability in the sandbox (parallel) and links chains."""

    name = "exploit"
    persona = PERSONAS["exploit"]

    def __init__(self, max_workers: int = 4):
        self.max_workers = max(1, max_workers)

    def run(self, blackboard: Blackboard) -> int:
        candidates = blackboard.candidates()

        def prove(event) -> None:
            payload = event.payload
            try:
                result = run_exploit_sandbox(
                    payload["vuln_type"],
                    reconstruct_target_code(
                        Finding(
                            file=payload["file"],
                            line=payload["line"],
                            vuln_type=payload["vuln_type"],
                            payload=payload["payload"],
                            confidence=payload["confidence"],
                        )
                    ),
                )
            except Exception as exc:
                result = f"ERROR {exc}"
            kind = "confirmed" if result.startswith("CONFIRMED_EXPLOITABLE") else "rejected"
            blackboard.post(
                agent=self.name,
                kind=kind,
                payload={**payload, "sandbox": result[:300]},
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            list(pool.map(prove, candidates))

        self._link_chains(blackboard)
        return len(blackboard.confirmed())

    def _link_chains(self, blackboard: Blackboard) -> None:
        """Findings in the same file form a chain (same attack surface)."""
        confirmed = blackboard.confirmed()
        by_file: Dict[str, List[Any]] = {}
        for event in confirmed:
            by_file.setdefault(event.payload["file"], []).append(event.payload)
        for file, members in by_file.items():
            if len(members) < 2:
                continue
            blackboard.add_chain(
                {
                    "file": file,
                    "members": [{"line": m["line"], "vuln_type": m["vuln_type"]} for m in members],
                    "note": (
                        f"{len(members)} confirmed findings share {file} — patching one "
                        "may affect the others; review together."
                    ),
                }
            )


class PatchAgent:
    """Generates and verifies patches for confirmed findings."""

    name = "patch"
    persona = PERSONAS["patch"]

    def __init__(self, patch_loop: Optional[PatchLoop] = None):
        self.patch_loop = patch_loop or PatchLoop()

    def run(self, blackboard: Blackboard) -> int:
        confirmed = blackboard.confirmed()
        for event in confirmed:
            payload = event.payload
            try:
                result = self.patch_loop.run(
                    Finding(
                        file=payload["file"],
                        line=payload["line"],
                        vuln_type=payload["vuln_type"],
                        payload=payload["payload"],
                        confidence=payload["confidence"],
                    )
                )
            except Exception:
                continue
            blackboard.post(
                agent=self.name,
                kind="patch",
                payload={
                    **payload,
                    "needs_human": result.needs_human,
                    "attempts": result.attempts,
                    "confidence": (result.verification.confidence if result.verification else 0.0),
                    "diff": result.patch.diff if result.patch else "",
                },
            )
        return len(blackboard.patches())
