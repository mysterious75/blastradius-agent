"""Fetch public HackerOne reports (repo/source-code bug reports) for learning.

Public HackerOne reports expose full disclosure text at
``https://hackerone.com/reports/<id>.json`` (unauthenticated) — the HTML page
itself is JS-blocked, the JSON endpoint is not. This script downloads reports
by ID into a learning folder as raw JSON + a readable Markdown summary, and
maintains an index README.

Usage:
    python scripts/fetch_h1_reports.py --ids 1154542,2208621 --out learningfromreport
    python scripts/fetch_h1_reports.py --list reports.txt --out learningfromreport
"""

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict

USER_AGENT = "BlastRadius-learning/1.0"


def fetch_report(report_id: int) -> Dict[str, Any]:
    url = f"https://hackerone.com/reports/{report_id}.json"
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _attr(data: Dict[str, Any]) -> Dict[str, Any]:
    inner = data.get("data", data)
    if isinstance(inner, dict):
        return inner.get("attributes", inner)
    return inner


def extract_meta(data: Dict[str, Any]) -> Dict[str, Any]:
    a = _attr(data)
    weakness = a.get("weakness") or {}
    severity = a.get("severity") or {}
    return {
        "id": a.get("report_id") or a.get("id"),
        "title": a.get("title", ""),
        "state": a.get("state", ""),
        "severity": severity.get("rating") or a.get("severity_rating"),
        "cwe": weakness.get("external_id") or a.get("weakness_identifier"),
        "weakness": weakness.get("name"),
        "reported_at": a.get("reported_at"),
        "disclosed_at": a.get("disclosed_at"),
        "bounty": a.get("bounty_amount"),
        "reporter": (a.get("reporter") or {}).get("username") or a.get("reporter_username"),
        "program": (a.get("program") or {}).get("handle") or a.get("program_handle"),
        "info": a.get("vulnerability_information", ""),
    }


def _slug(title: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-").lower()[:60]
    return slug or "report"


def build_markdown(meta: Dict[str, Any]) -> str:
    lines = [
        f"# HackerOne Report #{meta['id']} — {meta['title']}",
        "",
        f"- **Program:** {meta['program'] or 'unknown'}",
        f"- **Severity:** {meta['severity'] or 'n/a'}",
        f"- **Weakness:** {meta['weakness'] or 'n/a'} ({meta['cwe'] or 'n/a'})",
        f"- **State:** {meta['state'] or 'n/a'}",
        f"- **Reporter:** {meta['reporter'] or 'n/a'}",
        f"- **Reported:** {meta['reported_at'] or 'n/a'}",
        f"- **Disclosed:** {meta['disclosed_at'] or 'n/a'}",
        f"- **Bounty:** {meta['bounty'] or 'n/a'}",
        "",
        "## Full disclosure",
        "",
    ]
    info = (meta.get("info") or "").strip()
    if info:
        lines.append(info)
    else:
        lines.append("_(no vulnerability_information in the public JSON)_")
    lines.append("")
    return "\n".join(lines)


def save_report(out_dir: Path, report_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
    meta = extract_meta(data)
    base = f"{report_id}_{_slug(meta.get('title', ''))}"
    (out_dir / f"{base}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out_dir / f"{base}.md").write_text(build_markdown(meta), encoding="utf-8")
    return meta


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Download public HackerOne reports")
    ap.add_argument("--ids", default="", help="comma-separated report IDs")
    ap.add_argument("--list", default="", help="file with one report ID per line")
    ap.add_argument("--out", default="learningfromreport", help="output folder")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between fetches")
    args = ap.parse_args(argv)

    ids: list[int] = []
    if args.ids:
        ids += [int(p) for p in args.ids.split(",") if p.strip().isdigit()]
    if args.list:
        ids += [
            int(line.strip())
            for line in Path(args.list).read_text(encoding="utf-8").splitlines()
            if line.strip().isdigit()
        ]
    ids = list(dict.fromkeys(ids))
    if not ids:
        print("no report IDs given (--ids or --list)", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    index = []
    ok, failed = 0, 0
    for report_id in ids:
        try:
            data = fetch_report(report_id)
            meta = save_report(out_dir, report_id, data)
            has_info = bool((meta.get("info") or "").strip())
            index.append(meta)
            print(f"[+] {report_id}: {meta.get('title', '?')} (info={'yes' if has_info else 'NO'})")
            ok += 1
        except Exception as exc:
            print(f"[-] {report_id}: {exc}")
            failed += 1
        time.sleep(args.delay)

    index_lines = [
        "# HackerOne Reports — Learning Folder",
        "",
        f"Downloaded {ok} report(s), {failed} failed. Source: public HackerOne",
        "disclosure JSON (`hackerone.com/reports/<id>.json`).",
        "",
        "| ID | Title | Severity | Weakness | State | Info |",
        "|---|---|---|---|---|---|",
    ]
    for meta in sorted(index, key=lambda m: str(m.get("id"))):
        index_lines.append(
            f"| #{meta.get('id')} | {meta.get('title', '?')} | "
            f"{meta.get('severity') or '-'} | {meta.get('weakness') or '-'} | "
            f"{meta.get('state') or '-'} | "
            f"{'yes' if (meta.get('info') or '').strip() else 'NO'} |"
        )
    (out_dir / "README.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    print(f"[*] saved {ok} report(s) to {out_dir} (README.md index updated)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
