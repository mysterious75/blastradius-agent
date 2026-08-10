"""Focused sub-task orchestrator — the open·kritt lesson applied to BlastRadius.

Instead of one giant agent conversation over a whole repo (which exhausts its
iteration budget on real targets), hunt in two phases:

1. **Deterministic scan + rank** — the pattern scanner finds every candidate
   cheaply, and ``rank_findings`` orders them by expected value.
2. **Focused sub-tasks** — the top-K findings each get their OWN small,
   bounded agent conversation (validate with the sandbox, patch if confirmed).
   One bad or runaway task cannot burn the whole budget; tasks are independent
   and can later be parallelized.

Run:  python -m blastradius.agent_tasks <repo-path> [top-k]
"""

import asyncio
import json
import sys
from typing import List, Optional

from blastradius.agent import _run_conversation, build_agent
from blastradius.hunter.ranking import (
    RankedFinding,
    classify_verdict,
    finding_key,
    rank_findings,
)

FOCUSED_TASK_INSTRUCTIONS = (
    "You are validating ONE security finding in isolation.\n"
    "1. Call run_exploit_sandbox with the finding's vuln_type and the vulnerable "
    "code to prove exploitability.\n"
    "2. If the sandbox confirms it, call generate_and_verify_patch.\n"
    "3. Reply with a short verdict only: EXPLOITABLE with a one-line reason, "
    "NOT_EXPLOITABLE with a one-line reason, or NEEDS_MANUAL_REVIEW.\n"
    "Use only these two tools. Stop as soon as you have a verdict."
)

DEFAULT_TASK_ITERATIONS = 8


def _finding_payload(finding) -> str:
    return json.dumps(
        {
            "file": finding.file,
            "line": finding.line,
            "vuln_type": finding.vuln_type,
            "payload": finding.payload,
            "confidence": finding.confidence,
            "severity": finding.severity,
            "description": finding.description,
        },
        default=str,
    )


async def run_focused_task(finding, agent: dict = None, max_iterations: int = DEFAULT_TASK_ITERATIONS) -> dict:
    """Validate a single finding in its own bounded conversation."""
    agent = agent or build_agent()
    messages = [
        {"role": "system", "content": FOCUSED_TASK_INSTRUCTIONS},
        {"role": "user", "content": _finding_payload(finding)},
    ]
    output = await _run_conversation(messages, agent, max_iterations)
    return {
        "finding": finding_key(finding),
        "file": finding.file,
        "line": finding.line,
        "vuln_type": finding.vuln_type,
        "output": output,
        "verdict": classify_verdict(output),
    }


async def run_focused_hunt(
    target: str,
    top_k: int = 5,
    agent: dict = None,
    max_task_iterations: int = DEFAULT_TASK_ITERATIONS,
    scan_repo=None,
) -> dict:
    """Deterministic scan -> rank -> focused per-finding sub-tasks -> re-rank.

    ``scan_repo`` is injectable for tests (defaults to CVEHunter().scan_repo).
    Returns an aggregate result with the ranked list, per-task outputs, and a
    verdict map that re-ranks findings once sandbox verdicts are known.
    """
    if scan_repo is None:
        from blastradius.hunter.scanner import CVEHunter

        scan_repo = CVEHunter().scan_repo
    findings = scan_repo(target)
    ranked = rank_findings(findings)
    top: List[RankedFinding] = ranked[:top_k]

    tasks = []
    verdicts = {}
    for r in top:
        task = await run_focused_task(r.finding, agent=agent, max_iterations=max_task_iterations)
        verdicts[finding_key(r.finding)] = task["verdict"]
        tasks.append({**task, "rank": r.rank, "score": r.score})

    re_ranked = rank_findings(findings, sandbox_verdicts=verdicts)
    return {
        "target": target,
        "total_findings": len(findings),
        "top_k": top_k,
        "ranked": ranked,
        "tasks": tasks,
        "verdicts": verdicts,
        "re_ranked": re_ranked,
    }


async def _demo(target: str, top_k: int) -> None:
    result = await run_focused_hunt(target, top_k=top_k)
    print(f"target={result['target']} findings={result['total_findings']} top_k={result['top_k']}")
    for t in result["tasks"]:
        print(
            f"  #{t['rank']} {t['vuln_type']:6} {t['verdict']:20} {t['file']}:{t['line']}  score={t['score']}"
        )


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    top_k = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    asyncio.run(_demo(target, top_k))
