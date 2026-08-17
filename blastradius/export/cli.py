"""Export CLI.

Usage:
    python -m blastradius.export --format sarif --output report.sarif
    python -m blastradius.export --format sarif2 --output report.sarif   # alias of sarif
    python -m blastradius.export --format sbom --output sbom.json        # CycloneDX 1.5
    python -m blastradius.export --format html --output report.html
    python -m blastradius.export --format csv --output findings.csv
    python -m blastradius.export --format json --input findings.json --output out.json
"""

import argparse
import json

from blastradius.export.exporter import FindingsExporter

_FORMAT_METHODS = {
    "sarif": "export_sarif",
    "sarif2": "export_sarif",
    "sbom": "export_sbom_cyclonedx",
}


def _load_findings(args) -> list:
    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            return json.load(fh)
    from blastradius.db.database import SQLiteDB

    return SQLiteDB().get_all_findings()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="blastradius-export")
    parser.add_argument(
        "--format",
        choices=["csv", "json", "sarif", "sarif2", "html", "markdown", "sbom"],
        default="markdown",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--input", default=None, help="findings JSON file (default: SQLite DB)")
    args = parser.parse_args(argv)

    findings = _load_findings(args)
    exporter = FindingsExporter(findings)
    method = _FORMAT_METHODS.get(args.format, f"export_{args.format}")
    getattr(exporter, method)(args.output)
    print(f"[+] exported {len(findings)} finding(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
