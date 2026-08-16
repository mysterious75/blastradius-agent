"""Filter HackerOne corpus CSV -> report IDs (bounty>0 OR high upvotes) AND repo-typical vuln classes."""
import csv, re, sys

SRC = r"D:\vora\New folder\mycli\blastradius-agent\learningfromreport\hackerone_reports_14833_corpus.csv"
OUT = r"D:\vora\New folder\mycli\blastradius-agent\reports5000\h1_ids_all.txt"
STATS = r"D:\vora\New folder\mycli\blastradius-agent\reports5000\h1_filter_stats.txt"

# Allowed vuln-type base names (matched case-insensitively on the part before " - ")
ALLOWED_TYPES = [
    "sql injection",
    "blind sql injection",
    "cross-site scripting",
    "code injection",
    "command injection",
    "os command injection",
    "deserialization",
    "server-side request forgery",
    "server side request forgery",
    "path traversal",
    "crlf injection",
    "xml external entities",
    "authentication bypass",
    "improper authentication",
    "improper restriction of authentication attempts",
    "improper authorization",
    "missing authorization",
    "incorrect authorization",
    "missing authentication for critical function",
    "remote code execution",
    "unexpected code execution",
    "resource injection",
    "remote file inclusion",
    "ldap injection",
    "xml injection",
    "format string",
]
# Title keyword fallback for classes not represented in vuln_type column
TITLE_KEYWORDS = ["ssti", "template injection", "prototype pollution", "crlf", "deserialization", "xxe"]

ID_RE = re.compile(r"hackerone\.com/reports/(\d+)")

rows = []
with open(SRC, encoding="utf-8", errors="replace") as f:
    r = csv.reader(f)
    header = next(r)
    for row in r:
        if len(row) < 6:
            continue
        rows.append(row)

def to_float(s):
    try:
        return float(s)
    except (ValueError, TypeError):
        return 0.0

def to_int(s):
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return 0

def type_ok(vtype, title):
    base = (vtype or "").split(" - ")[0].strip().lower()
    for a in ALLOWED_TYPES:
        if a in base:
            return True
    tl = (title or "").lower()
    for kw in TITLE_KEYWORDS:
        if kw in tl:
            return True
    return False

UPVOTE_THRESHOLD = 15  # "high upvotes"
matched = []
stats = {"total": len(rows), "bounty_gt0": 0, "upvotes_ge_threshold": 0}
for row in rows:
    program, title, link, upvotes, bounty, vtype = (list(row) + [""] * 6)[:6]
    b = to_float(bounty)
    u = to_int(upvotes)
    if b > 0:
        stats["bounty_gt0"] += 1
    if u >= UPVOTE_THRESHOLD:
        stats["upvotes_ge_threshold"] += 1
    if not (b > 0 or u >= UPVOTE_THRESHOLD):
        continue
    if not type_ok(vtype, title):
        continue
    m = ID_RE.search(link)
    if not m:
        continue
    matched.append((int(m.group(1)), program, title, u, b, vtype))

matched.sort(key=lambda x: -x[3])  # by upvotes desc
ids = [str(x[0]) for x in matched]
# dedupe preserving order
seen = set()
uniq = []
for i in ids:
    if i not in seen:
        seen.add(i)
        uniq.append(i)

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(uniq) + "\n")

with open(STATS, "w", encoding="utf-8") as f:
    f.write(f"total_rows={stats['total']}\n")
    f.write(f"rows_bounty_gt0={stats['bounty_gt0']}\n")
    f.write(f"rows_upvotes_ge_{UPVOTE_THRESHOLD}={stats['upvotes_ge_threshold']}\n")
    f.write(f"filtered_rows={len(matched)}\n")
    f.write(f"unique_ids={len(uniq)}\n")
    f.write("--- top 20 by upvotes ---\n")
    for x in matched[:20]:
        f.write(f"{x[0]} up={x[3]} bounty={x[4]} | {x[1]} | {x[2]} | {x[5]}\n")

print(f"total={stats['total']} bounty>0={stats['bounty_gt0']} upvotes>={UPVOTE_THRESHOLD}={stats['upvotes_ge_threshold']}")
print(f"filtered rows={len(matched)} unique_ids={len(uniq)}")
