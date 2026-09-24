"""Contagion CLI — pre-deployment DeFi blast-radius reports.

Usage:
    python -m blastradius.contagion map     --token rsETH --data data/seed_kelpdao_case.json
    python -m blastradius.contagion score   --token rsETH --data data/seed_kelpdao_case.json
    python -m blastradius.contagion baddebt --token rsETH --data data/seed_kelpdao_case.json
    python -m blastradius.contagion map     --token rsETH --data data/seed_kelpdao_case.json --ascii
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.schema import NodeKind
from blastradius.contagion.scoring import (
    BadDebtRow,
    score_blast_radius,
    simulate_token_collapse,
)


def _display():
    try:  # Rich display is nice-to-have; fall back to plain text.
        from blastradius.cli.display import RichDisplay

        return RichDisplay()
    except Exception:  # pragma: no cover - cosmetic fallback
        return None


def _print_table(headers, rows, title=None, display=None):
    if display is not None:
        try:
            display.print_table(headers, rows, title=title)
            return
        except Exception:  # pragma: no cover - cosmetic fallback
            pass
    if title:
        print(f"\n== {title} ==")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


def _ascii_map(radius, seed_id: str) -> str:
    """Render the contagion cascade as a tree (the KelpDAO map shape)."""
    children = {}
    for entry in radius.entries:
        parent = entry.path[-2] if len(entry.path) >= 2 else seed_id
        children.setdefault(parent, []).append(entry)

    lines = [f"{seed_id}  <-- SEED (this breaks)"]

    def walk(parent: str, prefix: str = "") -> None:
        kids = sorted(children.get(parent, []), key=lambda e: (e.hop, -e.tvl_usd))
        for i, kid in enumerate(kids):
            last = i == len(kids) - 1
            branch = "└── " if last else "├── "
            cont = "    " if last else "│   "
            lines.append(
                f"{prefix}{branch}[{kid.kind.value}] {kid.name}  (${kid.tvl_usd:,.0f})"
            )
            walk(kid.node_id, prefix + cont)

    walk(seed_id)
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-contagion",
        description="Pre-deployment DeFi composability blast-radius reports",
    )
    parser.add_argument(
        "command", choices=["map", "score", "baddebt", "dump"], help="report to produce"
    )
    parser.add_argument("--token", required=True, help="seed token symbol, e.g. rsETH")
    parser.add_argument("--data", required=True, help="graph snapshot JSON")
    parser.add_argument("--depth", type=int, default=5, help="max traversal depth")
    parser.add_argument(
        "--price-ratio",
        type=float,
        default=0.0,
        help="post-collapse price ratio for baddebt (0.0 = total loss)",
    )
    parser.add_argument(
        "--ascii", action="store_true", help="render map as an ASCII cascade tree"
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    data_path = Path(args.data)
    if not data_path.is_file():
        print(f"[!] graph snapshot not found: {data_path}", file=sys.stderr)
        return 2

    graph = DeFiContagionGraph.from_json(data_path)
    seed = graph.seed_id(NodeKind.TOKEN, args.token)
    if graph.backend.node(seed) is None:
        known = sorted(n.name for n in graph.backend.all_nodes() if n.kind is NodeKind.TOKEN)
        print(f"[!] unknown token {args.token!r}; known: {', '.join(known)}", file=sys.stderr)
        return 2

    display = _display()
    if display is not None and not args.json:
        try:
            display.print_banner()
        except Exception:  # pragma: no cover - cosmetic fallback
            pass

    if args.command == "dump":
        print(json.dumps(graph.to_dict(), indent=2))
        return 0

    if args.command == "score":
        score = score_blast_radius(graph, seed, max_depth=args.depth)
        if args.json:
            print(json.dumps(score.__dict__, indent=2))
        else:
            _print_table(["Metric", "Value"], score.as_rows(), title="Blast Radius Score", display=display)
        return 0

    if args.command == "baddebt":
        rows: list[BadDebtRow] = simulate_token_collapse(graph, seed, price_ratio=args.price_ratio)
        if args.json:
            print(json.dumps([r.__dict__ | {"outcome": r.outcome} for r in rows], indent=2))
            return 0
        if not rows:
            print(f"[*] no lending market lists {args.token} as collateral")
            return 0
        table = [
            [
                r.market_name,
                r.protocol,
                f"{r.collateral_at_risk_usd:,.0f}",
                f"{r.debt_against_token_usd:,.0f}",
                f"{r.backstop_buffer_usd:,.0f}",
                f"{r.uncovered_loss_usd:,.0f}",
                r.outcome,
            ]
            for r in rows
        ]
        _print_table(
            ["Market", "Protocol", "Coll. at risk", "Debt vs token", "Backstop", "Uncovered", "Outcome"],
            table,
            title=f"Bad Debt if {args.token} -> {args.price_ratio:.2f}",
            display=display,
        )
        total = sum(r.uncovered_loss_usd for r in rows)
        print(f"\n[*] total uncovered loss: ${total:,.0f}")
        return 0

    # command == "map"
    radius = graph.blast_radius(seed, max_depth=args.depth)
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "node_id": e.node_id,
                        "kind": e.kind.value,
                        "name": e.name,
                        "hop": e.hop,
                        "tvl_usd": e.tvl_usd,
                        "via": e.via,
                        "path": list(e.path),
                    }
                    for e in radius.entries
                ],
                indent=2,
            )
        )
        return 0

    if args.ascii:
        print(_ascii_map(radius, seed))
    else:
        _print_table(
            ["Hop", "Kind", "Name", "TVL (USD)", "Via"], radius.rows(), title="Contagion Map", display=display
        )
    print(
        f"\n[*] {radius.node_count} affected node(s), depth {radius.depth}, "
        f"reachable TVL ${radius.total_tvl_usd:,.0f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
