"""Blast radius CLI — map a repo's dependencies to affected repos.

Usage:
    python -m blastradius.blast_radius --repo ./path
    python -m blastradius.blast_radius --repo ./path --backend memory
"""

import argparse

from pathlib import Path

from blastradius.blast_radius.graph import BlastRadiusGraph, parse_dependencies


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-blast-radius",
        description="Map a repo's dependencies to affected repos (blast radius)",
    )
    parser.add_argument("--repo", required=True, help="path to a repo")
    parser.add_argument(
        "--backend", choices=["auto", "memory", "neo4j"], default="auto",
        help="graph backend (default: neo4j with in-memory fallback)",
    )
    args = parser.parse_args(argv)

    graph = BlastRadiusGraph(backend=None if args.backend == "auto" else args.backend)
    repo_name = Path(args.repo).name or "unknown"
    graph.add_repo(repo_name, str(Path(args.repo).resolve()))

    deps = parse_dependencies(args.repo)
    for name, version in deps:
        graph.add_package(name, version)
        graph.link_package_to_repo(name, repo_name)

    if not deps:
        print(f"[*] No dependencies found in {args.repo}")

    for name, version in deps:
        affected = graph.query_blast_radius(name)
        print(f"Package {name} v{version} affects {len(affected)} repos: {affected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
