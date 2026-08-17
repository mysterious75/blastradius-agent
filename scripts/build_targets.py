"""Build a bounty-hunting TARGETS LIST from the local report corpus.

Extracts unique github.com/{owner}/{repo} targets from the GHSA corpus
(34,425 advisories — real CVEs in open-source repos) and cross-references
with the HackerOne corpus CSV for bug-bounty programs.

Outputs:
    targets/targets_list.json    machine-readable
    targets/README.md            human summary (counts + how to use)
"""

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GHSA = ROOT / "reports5000" / "ghsa_corpus.json"
CORPUS = ROOT / "learningfromreport" / "hackerone_reports_14833_corpus.csv"
OUT = ROOT / "targets"

_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
_SKIP = {"github", "advisory-database", "gists", "orgs", "sponsors", "users"}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # 1) GHSA refs -> repo counts
    repos: Counter = Counter()
    by_repo: dict = defaultdict(list)
    ghsa = json.loads(GHSA.read_text(encoding="utf-8"))
    for adv in ghsa.get("advisories", []):
        for ref in adv.get("references", []) or []:
            m = _REPO_RE.search(ref or "")
            if not m:
                continue
            owner, name = m.group(1).lower(), m.group(2).lower()
            if owner in _SKIP or name in _SKIP:
                continue
            repo = f"{owner}/{name}"
            repos[repo] += 1
            by_repo[repo].append(adv.get("id"))
    top_repos = [
        {
            "repo": r,
            "advisories": n,
            "ghsa_ids": by_repo[r][:5],
            "max_severity": _max_sev(by_repo[r], ghsa),
        }
        for r, n in repos.most_common(400)
    ]

    # 2) HackerOne corpus -> program bounty rows (top by upvotes)
    h1 = []
    if CORPUS.is_file():
        with CORPUS.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    up = int(row.get("upvotes") or 0)
                except ValueError:
                    up = 0
                h1.append(
                    {
                        "program": row.get("program", ""),
                        "title": row.get("title", ""),
                        "upvotes": up,
                        "bounty": row.get("bounty", ""),
                        "link": row.get("link", ""),
                    }
                )
    h1.sort(key=lambda r: r["upvotes"], reverse=True)

    data = {
        "counts": {
            "ghsa_advisories": ghsa.get("count"),
            "ghsa_unique_repos": len(repos),
            "h1_corpus_rows": len(h1),
            "top_repos": len(top_repos),
        },
        "ghsa_repos": top_repos,
        "hackerone_top_programs": h1[:150],
    }
    (OUT / "targets_list.json").write_text(json.dumps(data, indent=1), encoding="utf-8")

    lines = [
        "# Bounty-Hunting Targets List",
        "",
        f"Built from the local corpus: **{ghsa.get('count')} GHSA advisories** "
        f"→ **{len(repos)} unique open-source repos**; "
        f"**{len(h1)} HackerOne corpus rows** (program-level).",
        "",
        "## How to use",
        "",
        "1. **Open-source repos with real CVEs (GHSA)** — clone + `python -m blastradius.agents --target <repo>`;"
        " findings are pattern-proven, then verify manually. These are patch-verification + re-audit targets.",
        "2. **HackerOne programs with PUBLIC repos** (GitLab CE, Nextcloud, Rocket.Chat, Mattermost, Node.js,"
        " curl, RubyGems, Django, Hyperledger, Kubernetes, Airflow, Concrete CMS...) — scan the public repo,"
        " submit findings to their bug-bounty program (authorized only).",
        "3. Always check the program's scope & rules before testing (authorized use only).",
        "",
        "## Top 25 GHSA repos by advisory count",
        "",
        "| Repo | Advisories | Top severity |",
        "|---|---|---|",
    ]
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    for r in sorted(
        top_repos[:25], key=lambda x: (sev_order.get(x["max_severity"], 9), -x["advisories"])
    ):
        lines.append(f"| {r['repo']} | {r['advisories']} | {r['max_severity']} |")
    lines += [
        "",
        "## Top HackerOne programs (by upvotes)",
        "",
        "| Program | Upvotes |",
        "|---|---|",
    ]
    for r in h1[:40]:
        lines.append(f"| {r['program']} | {r['upvotes']} |")
    (OUT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[targets] {len(repos)} unique repos, {len(h1)} H1 rows -> {OUT}")
    return 0


def _max_sev(ids, ghsa):
    sev = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "LOW": 0}
    best = "LOW"
    by_id = {a["id"]: a for a in ghsa.get("advisories", [])}
    for i in ids:
        s = (by_id.get(i) or {}).get("severity", "")
        if sev.get(s, -1) > sev.get(best, -1):
            best = s
    return best


if __name__ == "__main__":
    raise SystemExit(main())
