"""FullPipeline CLI — run the end-to-end pipeline on one target.

Usage:
    python -m blastradius.pipeline_cli --target https://github.com/user/repo
    python -m blastradius.pipeline_cli --target ./local/path
    python -m blastradius.pipeline_cli --target ./local/path --reports-dir out
"""

import argparse

from blastradius.cli.display import RichDisplay
from blastradius.pipeline import FullPipeline


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-pipeline",
        description="Run the full BlastRadius pipeline (scan → exploit → patch → report)",
    )
    parser.add_argument("--target", required=True, help="GitHub repo URL or local path")
    parser.add_argument("--reports-dir", default="reports")
    args = parser.parse_args(argv)

    display = RichDisplay()
    display.print_banner()

    pipeline = FullPipeline(reports_dir=args.reports_dir)
    result = pipeline.run(args.target)

    print(f"[*] Target:          {result.target}")
    print(f"[*] Files scanned:   {result.files_scanned}")
    print(f"[*] Findings:        {len(result.findings)}")
    print(f"[*] Confirmed:       {len(result.confirmed)}")
    print(f"[*] Patches:         {len(result.patches)}")
    print(f"[*] Reports saved:   {len(result.reports)}")
    for path in result.reports:
        print(f"    - {path}")

    if result.findings:
        display.print_findings_table(result.findings)
    display.print_stats_panel(
        {
            "total_scans": 1,
            "confirmed_cves": len(result.confirmed),
            "patches_generated": len(result.patches),
            "success_rate": 100.0 if result.findings else 0.0,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
