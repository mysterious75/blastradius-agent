"""python -m blastradius.agents — run the multi-agent graph.

Runs ReconAgent → ExploitAgent (parallel) → PatchAgent over a target, sharing
a blackboard, and prints the agent-graph report. Confirmed findings also get
disclosure reports saved to ``--reports-dir``.

Usage:
    python -m blastradius.agents --target ./path-or-url
"""

import argparse
import json
import time
from pathlib import Path

from blastradius.agents.orchestrator import AgentGraph


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="BlastRadius multi-agent graph")
    ap.add_argument("--target", required=True, help="GitHub URL or local path")
    ap.add_argument("--exploit-workers", type=int, default=4)
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--reports-dir", default="reports")
    args = ap.parse_args(argv)

    graph = AgentGraph(exploit_workers=args.exploit_workers, min_confidence=args.min_confidence)
    print(f"[*] agent graph: recon -> exploit(x{args.exploit_workers}) -> patch")
    result = graph.run(args.target)

    print(
        f"[*] candidates: {len(result.candidates)} | "
        f"confirmed: {len(result.confirmed)} | rejected: {len(result.rejected)} | "
        f"patches: {len(result.patches)} | chains: {len(result.chains)}"
    )
    for chain in result.chains:
        print(f"[*] chain: {chain['note']}")

    out_dir = Path(args.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    path = out_dir / f"agent_graph_{stamp}.json"
    path.write_text(
        json.dumps(
            {
                "target": result.target,
                "agents": result.agents,
                "files_scanned": result.files_scanned,
                "elapsed_seconds": result.elapsed_seconds,
                "counts": {
                    "candidates": len(result.candidates),
                    "confirmed": len(result.confirmed),
                    "rejected": len(result.rejected),
                    "patches": len(result.patches),
                    "chains": len(result.chains),
                },
                "confirmed": result.confirmed,
                "patches": result.patches,
                "chains": result.chains,
                "events": [
                    {"agent": e.agent, "kind": e.kind, "at": round(e.at, 2)} for e in result.events
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[*] graph report: {path}")
    return 1 if result.confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
