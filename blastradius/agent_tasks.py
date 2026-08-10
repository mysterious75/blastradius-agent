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
from blastradius.hunter.scanner import reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox

FOCUSED_TASK_INSTRUCTIONS = (
    "You are reviewing ONE security finding where the sandbox could not reach "
    "a conclusion.\n"
    "1. The user message includes 'reconstructed_target' (runnable code that "
    "defines target(user_input)) and 'sandbox_output' (what the sandbox said).\n"
    "2. Re-run run_exploit_sandbox(vuln_type, reconstructed_target) if useful.\n"
    "3. Reply with a short verdict only: EXPLOITABLE, NOT_EXPLOITABLE, or "
    "NEEDS_MANUAL_REVIEW, each with a one-line reason.\n"
    "Use only these tools. Stop as soon as you have a verdict."
)

DEFAULT_TASK_ITERATIONS = 8


def _finding_payload(finding, sandbox_output: str = "") -> str:
    try:
        reconstructed = reconstruct_target_code(finding)
    except Exception:
        reconstructed = ""
    return json.dumps(
        {
            "file": finding.file,
            "line": finding.line,
            "vuln_type": finding.vuln_type,
            "payload": finding.payload,
            "confidence": finding.confidence,
            "severity": finding.severity,
            "description": finding.description,
            "code_context": finding.context,
            "reconstructed_target": reconstructed,
            "sandbox_output": sandbox_output,
        },
        default=str,
    )


async def run_focused_task(finding, agent: dict = None, max_iterations: int = DEFAULT_TASK_ITERATIONS) -> dict:
    """Validate a single finding: deterministic sandbox first, LLM only when needed.

    The sandbox is authoritative — the LLM's free-text verdicts were unreliable
    to parse. When the sandbox is conclusive (exploitable / not_exploitable /
    unsupported) the task returns immediately without any LLM call; the LLM
    runs only for inconclusive cases to add reasoning.
    """
    agent = agent or build_agent()
    try:
        sandbox_output = run_exploit_sandbox(
            finding.vuln_type, reconstruct_target_code(finding)
        )
    except Exception as exc:
        sandbox_output = f"error: {exc}"
    sandbox_verdict = classify_verdict(sandbox_output)
    if sandbox_verdict in ("exploitable", "not_exploitable", "unsupported"):
        return {
            "finding": finding_key(finding),
            "file": finding.file,
            "line": finding.line,
            "vuln_type": finding.vuln_type,
            "output": sandbox_output,
            "verdict": sandbox_verdict,
            "sandbox_output": sandbox_output,
            "sandbox_verdict": sandbox_verdict,
            "llm_output": "",
        }

    messages = [
        {"role": "system", "content": FOCUSED_TASK_INSTRUCTIONS},
        {"role": "user", "content": _finding_payload(finding, sandbox_output)},
    ]
    output = await _run_conversation(messages, agent, max_iterations)
    return {
        "finding": finding_key(finding),
        "file": finding.file,
        "line": finding.line,
        "vuln_type": finding.vuln_type,
        "output": output,
        "verdict": classify_verdict(output),
        "sandbox_output": sandbox_output,
        "sandbox_verdict": sandbox_verdict,
        "llm_output": output,
    }


async def run_focused_hunt(
    target: str,
    top_k: int = 5,
    agent: dict = None,
    max_task_iterations: int = DEFAULT_TASK_ITERATIONS,
    scan_repo=None,
    weights: Optional[dict] = None,
) -> dict:
    """Deterministic scan -> rank -> focused per-finding sub-tasks -> re-rank.

    Sub-tasks run CONCURRENTLY (asyncio.gather) since they are independent —
    one slow task no longer delays the rest. ``scan_repo`` is injectable for
    tests (defaults to CVEHunter().scan_repo); ``weights`` overrides the rank
    weights (see hunter.ranking.rank_weights).
    Returns an aggregate result with the ranked list, per-task outputs, and a
    verdict map that re-ranks findings once sandbox verdicts are known.
    """
    if scan_repo is None:
        from blastradius.hunter.scanner import CVEHunter

        scan_repo = CVEHunter().scan_repo
    findings = scan_repo(target)
    ranked = rank_findings(findings, weights=weights)
    top: List[RankedFinding] = ranked[:top_k]

    # independent sub-tasks run in parallel
    results = await asyncio.gather(
        *(
            run_focused_task(r.finding, agent=agent, max_iterations=max_task_iterations)
            for r in top
        )
    )

    tasks = []
    verdicts = {}
    for r, task in zip(top, results):
        verdicts[finding_key(r.finding)] = task["verdict"]
        tasks.append({**task, "rank": r.rank, "score": r.score})

    re_ranked = rank_findings(findings, sandbox_verdicts=verdicts, weights=weights)
    # expose the verdict-adjusted score on each task (verified rise, ruled-out sink)
    adjusted = {finding_key(r.finding): r.score for r in re_ranked}
    for task in tasks:
        task["score"] = adjusted.get(task["finding"], task["score"])
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
