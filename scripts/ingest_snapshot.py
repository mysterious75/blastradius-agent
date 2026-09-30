#!/usr/bin/env python3
"""Build the contagion snapshot for the public calculator from LOCAL data.

Unlike ``scripts/ingest_live.py`` (which calls live DeFiLlama APIs), this
script builds deterministically from the snapshots in ``data/ingest/``
(produced by ``scripts/download_defi_data.py``) plus the keyless AaveKit
GraphQL API, and fills backstop buffers from on-chain reads. Use ``--live``
to include the live fetchers; without it the build is fully offline and
reproducible.

Usage::

    python3 scripts/ingest_snapshot.py --out-dir docs/data
    python3 scripts/ingest_snapshot.py --live --out-dir /tmp/snap

Attribution is written into the snapshot itself (``provenance``).
See ``DATA_ATTRIBUTION.md``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from blastradius.contagion.loaders import snapshot as snapshot_loader  # noqa: E402
from blastradius.contagion.schema import NodeKind  # noqa: E402

INGEST_DIR = REPO_ROOT / "data" / "ingest"
OUT_DIR = REPO_ROOT / "docs" / "data"

ATTRIBUTION = {
    "data_sources": [
        "DeFiLlama free public APIs (https://api.llama.fi, https://yields.llama.fi)",
        "AaveKit GraphQL (https://api.v3.aave.com/graphql)",
        "Chainlink reference data + on-chain feeds",
        "Pyth Hermes price feeds",
        "LayerZero metadata/scan APIs",
        "Morpho Blue REST API",
        "On-chain reads via public RPC (backstop buffers)",
    ],
    "data_source_license_note": (
        "Figures are attributed to their sources and reproduced unmodified "
        "except for documented joins and field renames. No source endorses "
        "this project or is affiliated with it."
    ),
    "derived_fields_note": (
        "bad_debt_usd and uncovered_loss_usd are computed locally by "
        "blastradius.contagion.scoring.simulate_token_collapse. "
        "backstop_buffer_usd comes from on-chain reads where configured, "
        "else 0 (upper bound)."
    ),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ingest-dir", default=str(INGEST_DIR))
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    parser.add_argument("--top-protocols", type=int, default=200)
    parser.add_argument("--top-markets", type=int, default=100)
    parser.add_argument(
        "--live", action="store_true", help="also fetch live Aave markets + backstop buffers"
    )
    parser.add_argument(
        "--chains", nargs="+", type=int, default=[1, 42161, 8453], help="Aave chain ids for --live"
    )
    args = parser.parse_args(argv)

    graph = snapshot_loader.build_graph_from_snapshot(
        Path(args.ingest_dir), top_n_protocols=args.top_protocols, top_n_markets=args.top_markets
    )
    notes = [f"snapshot:{args.ingest_dir}"]

    if args.live:
        from blastradius.contagion.loaders import aave as aave_loader  # noqa: E402
        from blastradius.contagion.loaders import backstop as backstop_loader  # noqa: E402

        markets = aave_loader.fetch_markets(chain_ids=args.chains)
        print(f"[+] live Aave markets: {len(markets)}")
        live_graph = aave_loader.build_graph_from_aave(markets)
        for node in live_graph.backend.all_nodes():
            graph.backend.add_node(node)
        for edge in live_graph.backend.all_edges():
            graph.backend.add_edge(edge)
        notes.append(f"live-aave:{len(markets)}")

        buffers = backstop_loader.fetch_backstops()
        print(f"[+] live backstop buffers: {buffers}")
        notes.append(f"live-backstop:{len(buffers)}")

    nodes = graph.backend.all_nodes()
    edges = graph.backend.all_edges()
    by_kind = {k.value: sum(1 for n in nodes if n.kind is k) for k in NodeKind}

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "provenance": {
            **ATTRIBUTION,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "inputs": notes,
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
    print(f"[+] wrote {out_path} nodes {len(nodes)} {by_kind} | edges {len(edges)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
