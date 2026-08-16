import csv, json, re

SRC = r"learningfromreport/hackerone_reports_14833_corpus.csv"
rows = list(csv.DictReader(open(SRC, encoding="utf-8", errors="replace")))

KEY_VULNS = [
    "deserialization", "sqli", "sql injection", "xss", "ssti", "template",
    "rce", "remote code", "command injection", "path traversal", "prototype",
    "crlf", "ssrf", "code injection", "secret", "xxe", "xml external",
    "insecure deserialization", "heap overflow", "buffer", "use after free",
    "memory corruption", "os command", "type confusion", "race condition",
]

def score(r):
    try:
        uv = float(r["upvotes"] or 0)
    except ValueError:
        uv = 0
    try:
        bt = float(r["bounty"] or 0)
    except ValueError:
        bt = 0
    return uv, bt

def pick_id(r):
    m = re.search(r"reports/(\d+)", r["link"])
    return m.group(1) if m else None

# Candidates ranked by upvotes primarily, bounty secondarily, filtered to source-audit vuln types
filtered = []
for r in rows:
    vid = pick_id(r)
    if not vid:
        continue
    vt = (r["vuln_type"] or "").lower()
    if any(k in vt for k in KEY_VULNS) or vt == "":
        filtered.append((vid, r["program"], r["title"], r["upvotes"], r["bounty"], r["vuln_type"]))

# sort: known vuln type first (non-empty), then upvotes desc, bounty desc
def sort_key(x):
    vt = x[5]
    return (0 if vt else 1, -(float(x[3] or 0) or 0), -(float(x[4] or 0) or 0))

filtered.sort(key=sort_key)
seen = set()
out = []
for x in filtered:
    if x[0] not in seen:
        seen.add(x[0])
        out.append(x)

with open("learningfromreport/candidates.json", "w", encoding="utf-8") as f:
    json.dump(out[:200], f, indent=0)
print("total with id:", len(filtered), "unique:", len(out))
print("top 25:")
for x in out[:25]:
    print(x[0], "|", x[1], "| up:", x[3], "| bounty:", x[4], "|", x[5], "|", x[2][:60])
