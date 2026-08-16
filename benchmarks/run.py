"""Reproducible vulnerability-detection benchmark for BlastRadius.

Runs the real scanning pipeline against a local corpus of deliberately
vulnerable mini-apps, compares findings against each target's ground-truth
manifest, and reports precision / recall / F1 — and, with ``--verify``, how
many findings were actually *proven* exploitable by executing their PoC in the
sandbox.

Offline and deterministic by default: no network, no LLM, no Docker, and
learned FP rules are disabled so results are comparable across machines.
Add ``--verify`` to execute each candidate's PoC (needs Docker, or
``BLASTRADIUS_ALLOW_UNSANDBOXED=1`` for the documented dev fallback).

Usage:
    python benchmarks/run.py
    python benchmarks/run.py --verify
    python benchmarks/run.py --min-f1 0.5      # CI gate: exit 1 below F1
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


def _matches(finding, expected: dict) -> bool:
    """A finding hits an expected vulnerability when type and file match."""
    return (
        finding.vuln_type == expected["vuln_type"]
        and Path(finding.file).name == Path(expected["file"]).name
    )


def run_target(target_dir: Path, min_confidence: float, verify: bool) -> dict:
    """Scan a single corpus target (copied to a temp dir) and score it."""
    manifest = _load_manifest(target_dir)
    tmp = Path(tempfile.mkdtemp(prefix="br-bench-"))
    try:
        for item in target_dir.iterdir():
            if item.name == "manifest.json":
                continue
            dest = tmp / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        from blastradius.hunter import scanner as _scanner
        from blastradius.hunter.scanner import CVEHunter

        # Deterministic runs: ignore any user-learned FP rules on this machine.
        _scanner._load_learned_rules = lambda: {}

        findings = CVEHunter(min_confidence=min_confidence).scan_repo(str(tmp))

        proven = 0
        if verify:
            from blastradius.hunter.scanner import reconstruct_target_code
            from blastradius.tools.sandbox_tool import run_exploit_sandbox

            for f in findings:
                out = run_exploit_sandbox(f.vuln_type, reconstruct_target_code(f))
                if out.startswith("CONFIRMED_EXPLOITABLE"):
                    proven += 1

        expected = manifest.get("expected", [])
        hits = sum(1 for exp in expected if any(_matches(f, exp) for f in findings))
        reported = len(findings)
        precision = hits / reported if reported else 0.0
        recall = hits / len(expected) if expected else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

        return {
            "target": manifest.get("target", target_dir.name),
            "description": manifest.get("description", ""),
            "expected": len(expected),
            "reported": reported,
            "hits": hits,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "proven": proven,
            "verify": verify,
            "findings": [
                {
                    "file": Path(f.file).name,
                    "line": f.line,
                    "type": f.vuln_type,
                    "confidence": f.confidence,
                }
                for f in findings
            ],
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _render_markdown(summary: dict) -> str:
    lines = [
        "# BlastRadius Benchmark",
        "",
        f"Generated: `{summary['generated_at']}`  ",
        f"Corpus: `{summary['corpus']}`  ",
        f"Verify (sandbox PoC): `{summary['verify']}`  ",
        f"Min confidence: `{summary['min_confidence']}`  ",
        f"Elapsed: `{summary['elapsed_seconds']}s`",
        "",
        "| Target | Expected | Reported | Hits | Precision | Recall | F1 | Proven |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t in summary["targets"]:
        proven = f"{t['proven']}/{t['reported']}" if t["verify"] else "—"
        lines.append(
            f"| {t['target']} | {t['expected']} | {t['reported']} | {t['hits']} "
            f"| {t['precision']:.3f} | {t['recall']:.3f} | {t['f1']:.3f} | {proven} |"
        )
    tot = summary["totals"]
    proven = f"{tot['proven']}/{tot['reported']}" if summary["verify"] else "—"
    lines.append(
        f"| **Total** | **{tot['expected']}** | **{tot['reported']}** | **{tot['hits']}** "
        f"| **{tot['precision']:.3f}** | **{tot['recall']:.3f}** | **{tot['f1']:.3f}** "
        f"| **{proven}** |"
    )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default=str(ROOT / "corpus"), help="corpus directory")
    ap.add_argument("--out", default=str(ROOT / "results"), help="results directory")
    ap.add_argument(
        "--verify",
        action="store_true",
        help="execute each candidate's PoC in the sandbox and count proven findings",
    )
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--min-f1", type=float, default=0.0, help="exit 1 if overall F1 is below this")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    targets = sorted(p for p in corpus.iterdir() if (p / "manifest.json").is_file())
    if not targets:
        print(f"[bench] no targets (manifest.json) found under {corpus}", file=sys.stderr)
        return 2

    started = time.time()
    rows = [run_target(t, args.min_confidence, args.verify) for t in targets]
    elapsed = time.time() - started

    total = {k: sum(r[k] for r in rows) for k in ("expected", "reported", "hits", "proven")}
    precision = total["hits"] / total["reported"] if total["reported"] else 0.0
    recall = total["hits"] / total["expected"] if total["expected"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": str(corpus),
        "verify": args.verify,
        "min_confidence": args.min_confidence,
        "elapsed_seconds": round(elapsed, 2),
        "totals": {
            **total,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        },
        "targets": rows,
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    json_path = out_dir / f"benchmark-{stamp}.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "BENCHMARK.md").write_text(_render_markdown(summary), encoding="utf-8")

    print(_render_markdown(summary))
    print(f"[bench] JSON: {json_path}")

    if f1 < args.min_f1:
        print(f"[bench] FAIL: overall F1 {f1:.3f} < --min-f1 {args.min_f1}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
