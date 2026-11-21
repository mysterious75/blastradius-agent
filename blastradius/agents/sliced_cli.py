"""CLI for the threat-model and thin-slice audit agent.

Usage:
    python -m blastradius.agents.sliced_cli --target ./repo
    python -m blastradius.agents.sliced_cli --target ./repo --llm
"""

import argparse
import json
from pathlib import Path

from blastradius.agents.threat_slicing import ThreatSlicingAgent
from blastradius.logging_utils import configure_logging, get_logger

log = get_logger(__name__)


def _build_llm(args):
    if not args.llm:
        return None
    from blastradius.providers.client import LLMClient

    return LLMClient(provider=args.provider or None, model=args.model or None, verbose=False)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Threat-model + thin-slice audit")
    ap.add_argument("--target", required=True, help="local repository path")
    ap.add_argument("--out", default="reports/threat-slicing", help="output directory")
    ap.add_argument("--min-confidence", type=float, default=0.7)
    ap.add_argument("--max-files-per-slice", type=int, default=20)
    ap.add_argument("--llm", action="store_true", help="use the configured LLM provider")
    ap.add_argument("--provider", default="", help="LLM provider override")
    ap.add_argument("--model", default="", help="LLM model override")
    ap.add_argument(
        "--log-level",
        default=None,
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="log verbosity (default: BLASTRADIUS_LOG_LEVEL or INFO)",
    )
    args = ap.parse_args(argv)
    configure_logging(args.log_level)

    agent = ThreatSlicingAgent(
        llm=_build_llm(args),
        min_confidence=args.min_confidence,
        max_files_per_slice=args.max_files_per_slice,
    )
    result = agent.run(args.target)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "threat-model.md").write_text(result.threat_model.to_markdown(), encoding="utf-8")
    (out_dir / "sliced-audit.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )

    log.info(
        "[slice] threat_model=%s slices=%s candidates=%s confirmed=%s",
        result.threat_model.source,
        len(result.slices),
        len(result.findings),
        len(result.confirmed),
    )
    for item in result.slices:
        log.info("[slice] %s: %s file(s)", item.name, len(item.files))
    log.info("[slice] report: %s", out_dir / "sliced-audit.json")
    return 1 if result.confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
