import urllib.request, json, csv, time, os

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0'}
DST = r"D:\vora\New folder\mycli\blastradius-agent\reports5000"

all_results = []
page = 1
max_pages = 40
while page <= max_pages:
    url = f"https://bugcrowd.com/crowdstream.json?filter_by=disclosures&page={page}"
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=40) as r:
            j = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"page {page} ERR {e}")
        break
    results = j.get("results") or []
    if not results:
        print(f"page {page}: empty, stopping")
        break
    all_results.extend(results)
    meta = j.get("pagination_meta") or {}
    print(f"page {page}: +{len(results)} (total {len(all_results)}) total_pages={meta.get('total_pages')}")
    # stop if we've hit the last page
    if page >= int(meta.get("total_pages") or 9999):
        break
    page += 1
    time.sleep(0.4)

with open(os.path.join(DST, "bugcrowd_disclosures.json"), "w", encoding="utf-8") as f:
    json.dump(all_results, f, indent=1)
print("saved bugcrowd_disclosures.json with", len(all_results), "entries")

# CSV
keys = ["disclosure_report_url", "title", "program", "target", "researcher", "priority", "disclosed_at"]
with open(os.path.join(DST, "bugcrowd_disclosures.csv"), "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(keys)
    for r in all_results:
        w.writerow([(r.get(k) or "") for k in keys])
print("saved bugcrowd_disclosures.csv")

# annotate repo/source-based by slug keywords
kw = ["source", "git", "repository", "github", "deserial", "rce", "command", "injection", "chain", "sandbox"]
repoish = [r for r in all_results if any(k in ((r.get("disclosure_report_url") or "") + " " + (r.get("title") or "")).lower() for k in kw)]
print("entries whose slug/title suggests repo/source/PoC material:", len(repoish))
with open(os.path.join(DST, "bugcrowd_repo_flagged.txt"), "w", encoding="utf-8") as f:
    for r in repoish:
        f.write(f"{r.get('disclosure_report_url')}\t{r.get('title')}\t{r.get('program')}\t{r.get('disclosed_at')}\n")
