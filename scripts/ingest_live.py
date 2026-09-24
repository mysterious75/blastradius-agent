#!/usr/bin/env python3
"""Build the live DeFi contagion dataset used by the public calculator.

Reads DeFiLlama's free public JSON APIs and writes a self-describing snapshot
into ``docs/data/``. Nothing is scraped and nothing is fabricated: every
figure in the output is either copied from the API response or derived from
these by the documented formulas in ``blastradius/contagion/scoring.py``.

Usage::

    python3 scripts/ingest_live.py                       # the default market set
    python3 scripts/ingest_live.py --projects aave-v3 compound-v3 morpho-blue
    python3 scripts/ingest_live.py --min-tvl 20000000 --top 400

Attribution for the data is written into the snapshot itself (``provenance``)
and rendered in the site footer. See ``DATA_ATTRIBUTION.md``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from blastradius.contagion.loaders.collateral import (  # noqa: E402
    build_graph_from_lending_markets,
    fetch_lending_markets,
)
from blastradius.contagion.schema import NodeKind  # noqa: E402

DEFAULT_PROJECTS = ("aave-v3", "compound-v3", "morpho-blue", "sparklend", "fluid")
OUT_DIR = REPO_ROOT / "docs" / "data"

ATTRIBUTION = {
    "data_source": "DeFiLlama",
    "data_source_urls": [
        "https://yields.llama.fi/pools",
        "https://yields.llama.fi/lendBorrow",
    ],
    "data_source_site": "https://defillama.com",
    "data_source_license_note": (
        "DeFiLlama publishes this data through free public APIs for open use. "
        "Figures are attributed to DeFiLlama and are reproduced here unmodified "
        "except for the documented join and field renames. DeFiLlama does not "
        "endorse this project and is not affiliated with it."
    ),
    "derived_fields_note": (
        "bad_debt_usd and uncovered_loss_usd are computed locally by "
        "blastradius.contagion.scoring.simulate_token_collapse; they are not "
        "DeFiLlama figures. backstop_buffer_usd is not published by any free "
        "API and defaults to 0, which makes uncovered_loss_usd an UPPER BOUND."
    ),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--projects",
        nargs="+",
        default=list(DEFAULT_PROJECTS),
        help="DeFiLlama project slugs to include",
    )
    parser.add_argument("--chain", default=None, help="restrict to one chain")
    parser.add_argument("--min-tvl", type=float, default=1_000_000.0, help="min market TVL in USD")
    parser.add_argument("--top", type=int, default=400, help="keep at most N markets")
    parser.add_argument("--out-dir", default=str(OUT_DIR), help="output directory")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_markets = []
    for project in args.projects:
        rows = fetch_lending_markets(
            project=project, chain=args.chain, min_tvl_usd=args.min_tvl
        )
        print(f"[+] {project:14} {len(rows):4d} lending markets")
        all_markets.extend(rows)

    all_markets.sort(key=lambda r: -r["tvl_usd"])
    if args.top:
        all_markets = all_markets[: args.top]
    print(f"[=] keeping {len(all_markets)} markets (top {args.top} by TVL)")

    graph = build_graph_from_lending_markets(all_markets)
    nodes = graph.backend.all_nodes()
    edges = graph.backend.all_edges()
    by_kind = {k.value: sum(1 for n in nodes if n.kind is k) for k in NodeKind}

    snapshot = {
        "provenance": {
            **ATTRIBUTION,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "projects": args.projects,
            "chain_filter": args.chain,
            "min_tvl_usd": args.min_tvl,
            "market_count": len(all_markets),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "disclaimer": (
                "Informational risk estimates only. Not financial, legal or "
                "investment advice. Figures are point-in-time and stale the "
                "moment they are written."
            ),
        },
        "graph": graph.to_dict(),
    }

    out_path = out_dir / "blast-graph.json"
    out_path.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    print(f"[+] wrote {out_path.relative_to(REPO_ROOT)}")
    print(f"    nodes {len(nodes)} {by_kind} | edges {len(edges)}")

    # A compact index the static site loads first.
    index = {
        "generated_at_utc": snapshot["provenance"]["generated_at_utc"],
        "market_count": len(all_markets),
        "projects": args.projects,
        "tokens": sorted(
            n.name for n in nodes if n.kind is NodeKind.TOKEN
        ),
        "protocols": sorted({n.name for n in nodes if n.kind is NodeKind.PROTOCOL}),
        "chains": sorted({n.name for n in nodes if n.kind is NodeKind.CHAIN}),
    }
    (out_dir / "blast-index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    print(f"[+] wrote {(out_dir / 'blast-index.json').relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
