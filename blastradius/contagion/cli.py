"""Contagion CLI — pre-deployment DeFi blast-radius reports + config audit.

Usage:
    python -m blastradius.contagion map     --token *** --data data/seed_kelpdao_case.json --ascii
    python -m blastradius.contagion score   --token *** --data data/seed_kelpdao_case.json
    python -m blastradius.contagion baddebt --token *** --data data/seed_kelpdao_case.json
    python -m blastradius.contagion audit   --config data/seed_kelpdao_config.json
    python -m blastradius.contagion ingest  --source defillama --project aave-v3 --out graph.json
    python -m blastradius.contagion ingest  --source whitelist --data listing.json --out graph.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from blastradius.contagion.config_audit import ConfigAuditor
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
    if not rows:
        print("  (no rows)")
        return
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
            lines.append(f"{prefix}{branch}[{kid.kind.value}] {kid.name}  (${kid.tvl_usd:,.0f})")
            walk(kid.node_id, prefix + cont)

    walk(seed_id)
    return "\n".join(lines)


def _load_graph(path: Path) -> DeFiContagionGraph:
    return DeFiContagionGraph.from_json(path)


def _cmd_map(args, graph, seed, display) -> int:
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


def _cmd_score(args, graph, seed, display) -> int:
    score = score_blast_radius(graph, seed, max_depth=args.depth)
    if args.json:
        print(json.dumps(score.__dict__, indent=2))
    else:
        _print_table(["Metric", "Value"], score.as_rows(), title="Blast Radius Score", display=display)
    return 0


def _cmd_baddebt(args, graph, seed, display) -> int:
    rows = simulate_token_collapse(graph, seed, price_ratio=args.price_ratio)
    if args.json:
        print(json.dumps([r.__dict__ | {"outcome": r.outcome} for r in rows], indent=2))
        return 0
    if not rows:
        print(f"[*] no lending market lists {args.token} as collateral")
        return 0
    _print_table(
        ["Market", "Protocol", "Coll. at risk", "Debt vs token", "Backstop", "Uncovered", "Outcome"],
        [
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
        ],
        title=f"Bad Debt if {args.token} -> {args.price_ratio:.2f}",
        display=display,
    )
    print(f"\n[*] total uncovered loss: ${sum(r.uncovered_loss_usd for r in rows):,.0f}")
    return 0


def _cmd_audit(args, display) -> int:
    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"[!] config snapshot not found: {config_path}", file=sys.stderr)
        return 2
    config = json.loads(config_path.read_text(encoding="utf-8"))
    report = ConfigAuditor().audit(config)

    if args.json:
        print(
            json.dumps(
                {
                    "target": report.target,
                    "worst_severity": report.worst_severity,
                    "passed": report.passed,
                    "counts": report.counts(),
                    "findings": [f.__dict__ for f in report.sorted_findings()],
                },
                indent=2,
            )
        )
    else:
        print(f"\nTarget: {report.target}")
        _print_table(
            ["Sev", "Rule", "Target", "Finding"], report.rows(), title="Configuration Audit", display=display
        )
        counts = report.counts()
        summary = "  ".join(f"{k}={v}" for k, v in counts.items() if v)
        print(f"\n[*] worst: {report.worst_severity} | {summary or 'no findings'}")
        if not args.quiet:
            for f in report.sorted_findings():
                if f.severity in ("CRITICAL", "HIGH"):
                    print(f"\n  !! {f.severity} {f.rule_id} on {f.target}")
                    print(f"     {f.title}")
                    print(f"     fix: {f.remediation}")

    # Non-zero exit when the config is not safe to ship.
    return 0 if report.passed else 1


def _cmd_ingest(args) -> int:
    from blastradius.contagion.loaders.collateral import (
        build_graph_from_pools,
        build_graph_from_whitelist,
        fetch_pools,
    )

    if args.source == "defillama":
        pools = fetch_pools(project=args.project, chain=args.chain, min_tvl_usd=args.min_tvl)
        graph = build_graph_from_pools(pools, top_n=args.top)
        print(f"[*] ingested {len(pools)} pool row(s) from DeFiLlama yields"
              + (f" (project={args.project})" if args.project else ""))
    else:
        if not args.data:
            print("[!] --source whitelist requires --data <listing.json>", file=sys.stderr)
            return 2
        graph = build_graph_from_whitelist(args.data)
        print(f"[*] ingested whitelist snapshot {args.data}")

    nodes = graph.backend.all_nodes()
    edges = graph.backend.all_edges()
    print(f"[*] graph: {len(nodes)} nodes, {len(edges)} edges")

    if args.out:
        graph.to_json(args.out)
        print(f"[*] wrote {args.out}")
    else:
        print(json.dumps(graph.to_dict(), indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-contagion",
        description="Pre-deployment DeFi composability blast-radius reports + config audit",
    )
    parser.add_argument(
        "command",
        choices=["map", "score", "baddebt", "audit", "ingest", "dump"],
        help="report to produce",
    )
    parser.add_argument("--token", help="seed token symbol, e.g. rsETH")
    parser.add_argument("--data", help="graph snapshot JSON (map/score/baddebt/dump)")
    parser.add_argument("--config", help="configuration snapshot JSON (audit)")
    parser.add_argument("--depth", type=int, default=5, help="max traversal depth")
    parser.add_argument(
        "--price-ratio", type=float, default=0.0, help="post-collapse price ratio for baddebt"
    )
    parser.add_argument("--ascii", action="store_true", help="render map as an ASCII cascade tree")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress per-finding detail (audit)")
    # ingest options
    parser.add_argument("--source", choices=["defillama", "whitelist"], help="ingest source")
    parser.add_argument("--project", help="DeFiLlama project filter, e.g. aave-v3")
    parser.add_argument("--chain", help="chain filter, e.g. Ethereum")
    parser.add_argument("--min-tvl", type=float, default=1_000_000.0, help="min pool TVL (USD)")
    parser.add_argument("--top", type=int, default=None, help="keep only the N largest pools")
    parser.add_argument("--out", help="write the built graph here (ingest)")
    args = parser.parse_args(argv)

    display = _display()

    if args.command == "ingest":
        return _cmd_ingest(args)

    if args.command == "audit":
        return _cmd_audit(args, display)

    if not args.data:
        print(f"[!] --data is required for '{args.command}'", file=sys.stderr)
        return 2
    data_path = Path(args.data)
    if not data_path.is_file():
        print(f"[!] graph snapshot not found: {data_path}", file=sys.stderr)
        return 2

    graph = _load_graph(data_path)

    if args.command == "dump":
        print(json.dumps(graph.to_dict(), indent=2))
        return 0

    if not args.token:
        print(f"[!] --token is required for '{args.command}'", file=sys.stderr)
        return 2
    seed = graph.seed_id(NodeKind.TOKEN, args.token)
    if graph.backend.node(seed) is None:
        known = sorted(n.name for n in graph.backend.all_nodes() if n.kind is NodeKind.TOKEN)
        print(f"[!] unknown token {args.token!r}; known: {', '.join(known)}", file=sys.stderr)
        return 2

    if display is not None and not args.json:
        try:
            display.print_banner()
        except Exception:  # pragma: no cover - cosmetic fallback
            pass

    return {
        "map": _cmd_map,
        "score": _cmd_score,
        "baddebt": _cmd_baddebt,
    }[args.command](args, graph, seed, display)


if __name__ == "__main__":
    raise SystemExit(main())
