"""CyberSecEval-3-style agentic evaluation for the BlastRadius agent graph.

Instead of scoring static detection only, the **full multi-agent graph**
(ReconAgent -> ExploitAgent -> PatchAgent over a shared blackboard, see
``blastradius.agents.orchestrator.AgentGraph``) runs against each corpus
target and the outcome is scored three ways against the ground-truth manifest:

* ``detection_recall`` — of the expected vulnerabilities, how many the graph
  surfaced as candidates (file basename + vuln_type must match).
* ``proof_precision`` — of everything the graph claims *confirmed* in the
  sandbox, how much corresponds to a real expected vulnerability. This is the
  **anti-hallucination score** and CyberSecEval's key metric: a confirmed
  finding carries a sandbox-executed ``[VULNERABLE]`` execution marker, so a
  high proof_precision proves the graph proves real bugs rather than
  asserting them.
* ``attack_success`` — did the graph actually *prove* the expected vuln
  exploitable (it appears in ``result.confirmed``).

Fail-closed: a finding without an execution marker can never inflate
proof_precision or attack_success — candidates stay candidates.

Each target is run from a fresh temp copy (corpus dirs are nested and the
graph scans recursively; copying avoids cross-target noise and matches
``benchmarks/run.py`` semantics). Offline and LLM-free.

Usage:
    python benchmarks/agent_eval.py
    python benchmarks/agent_eval.py --targets flask-sqli,hardcoded-secrets
    python benchmarks/agent_eval.py --min-attack-rate 1.0   # CI gate
"""

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_REPO_ROOT = ROOT.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))  # allow running without pip install


def _load_manifest(target_dir: Path) -> dict:
    with (target_dir / "manifest.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def _matches(row: dict, expected: dict) -> bool:
    """A finding hits an expected vulnerability when type and file match."""
    return (
        row.get("vuln_type") == expected["vuln_type"]
        and Path(str(row.get("file", ""))).name == Path(expected["file"]).name
    )


def run_target(target_dir: Path) -> dict:
    """Run the full agent graph on a corpus target (from a temp copy) and score it."""
    manifest = _load_manifest(target_dir)
    tmp = Path(tempfile.mkdtemp(prefix="br-agent-eval-"))
    try:
        for item in target_dir.iterdir():
            if item.name == "manifest.json":
                continue
            dest = tmp / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        from blastradius.agents.orchestrator import AgentGraph

        result = AgentGraph().run(str(tmp))

        expected = manifest.get("expected", [])
        candidates = result.candidates or []
        confirmed = result.confirmed or []

        matched_expected = sum(1 for exp in expected if any(_matches(c, exp) for c in candidates))
        confirmed_matching = sum(
            1 for conf in confirmed if any(_matches(conf, exp) for exp in expected)
        )
        detection_recall = matched_expected / len(expected) if expected else 0.0
        proof_precision = confirmed_matching / len(confirmed) if confirmed else 0.0
        attack_success = (
            1 if any(_matches(conf, exp) for conf in confirmed for exp in expected) else 0
        )

        return {
            "target": manifest.get("target", target_dir.name),
            "description": manifest.get("description", ""),
            "expected": len(expected),
            "candidates": len(candidates),
            "confirmed": len(confirmed),
            "expected_matched": matched_expected,
            "confirmed_matching_expected": confirmed_matching,
            "detection_recall": round(detection_recall, 3),
            "proof_precision": round(proof_precision, 3),
            "attack_success": attack_success,
            "candidate_vuln_types": sorted({c.get("vuln_type") for c in candidates}),
            "confirmed_vuln_types": sorted({c.get("vuln_type") for c in confirmed}),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _render_table(summary: dict) -> str:
    lines = [
        "# BlastRadius Agentic Evaluation (agent graph)",
        "",
        f"Generated: `{summary['generated_at']}`  ",
        f"Corpus: `{summary['corpus']}`  ",
        f"Elapsed: `{summary['elapsed_seconds']}s`",
        "",
        "| Target | Expected | Candidates | Confirmed | Recall | Attack |",
        "|---|---|---|---|---|---|",
    ]
    for row in summary["targets"]:
        mark = "YES" if row["attack_success"] else "no"
        lines.append(
            f"| {row['target']} | {row['expected']} | {row['candidates']} "
            f"| {row['confirmed']} | {row['detection_recall']:.3f} | {mark} |"
        )
    tot = summary["totals"]
    lines.append(
        f"| **Total** | **{tot['expected']}** | **{tot['candidates']}** "
        f"| **{tot['confirmed']}** | **{tot['detection_recall']:.3f}** "
        f"| **{tot['attack_success_rate']:.3f}** |"
    )
    lines += [
        "",
        f"Overall detection recall: `{tot['detection_recall']:.3f}`  ",
        f"Overall proof precision (anti-hallucination): `{tot['proof_precision']:.3f}`  ",
        f"Attack success rate: `{tot['attack_success_rate']:.3f}`",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(ROOT / "corpus"), help="corpus directory")
    ap.add_argument("--out", default=str(ROOT / "results"), help="results directory")
    ap.add_argument(
        "--targets",
        default="",
        help="comma-separated subset of target names (dir name or manifest 'target')",
    )
    ap.add_argument(
        "--min-attack-rate",
        type=float,
        default=0.0,
        help="exit 1 if the overall attack-success rate is below this (0 = report-only)",
    )
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    all_targets = sorted(p for p in corpus.iterdir() if (p / "manifest.json").is_file())
    wanted = {t.strip() for t in args.targets.split(",") if t.strip()}
    if wanted:
        targets = [
            p for p in all_targets if p.name in wanted or _load_manifest(p).get("target") in wanted
        ]
        if not targets:
            print(
                f"[agent-eval] no targets under {corpus} match --targets {args.targets}",
                file=sys.stderr,
            )
            return 2
    else:
        targets = all_targets
    if not targets:
        print(f"[agent-eval] no targets (manifest.json) found under {corpus}", file=sys.stderr)
        return 2

    started = time.time()
    rows = [run_target(t) for t in targets]
    elapsed = time.time() - started

    total_expected = sum(r["expected"] for r in rows)
    matched_expected = sum(r["expected_matched"] for r in rows)
    total_confirmed = sum(r["confirmed"] for r in rows)
    confirmed_matching = sum(r["confirmed_matching_expected"] for r in rows)
    attack_successes = sum(r["attack_success"] for r in rows)

    detection_recall = matched_expected / total_expected if total_expected else 0.0
    proof_precision = confirmed_matching / total_confirmed if total_confirmed else 0.0
    attack_success_rate = attack_successes / len(rows) if rows else 0.0

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": str(corpus),
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            "expected": total_expected,
            "matched_expected": matched_expected,
            "candidates": sum(r["candidates"] for r in rows),
            "confirmed": total_confirmed,
            "confirmed_matching_expected": confirmed_matching,
            "detection_recall": round(detection_recall, 3),
            "proof_precision": round(proof_precision, 3),
            "attack_success_rate": round(attack_success_rate, 3),
        },
        "targets": rows,
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    json_path = out_dir / f"agent_eval_{stamp}.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(_render_table(summary))
    print(f"[agent-eval] JSON: {json_path}")

    if attack_success_rate < args.min_attack_rate:
        print(
            f"[agent-eval] FAIL: attack success rate {attack_success_rate:.3f} "
            f"< --min-attack-rate {args.min_attack_rate}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
