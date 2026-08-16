import requests, json, re, time, csv

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"}

# Collect items across pages
items = []
seen = set()
for page in range(1, 6):  # up to 100 items
    u = f"https://bugcrowd.com/crowdstream.json?filter_by=disclosures&page={page}"
    try:
        r = requests.get(u, headers=H, timeout=30)
        j = r.json()
        res = j.get("results", [])
        if not res:
            break
        for it in res:
            if it.get("disclosure_report_url") and it["disclosure_report_url"] not in seen:
                seen.add(it["disclosure_report_url"])
                items.append(it)
        print(f"page {page}: +{len(res)} items, total {len(items)}")
        time.sleep(0.4)
    except Exception as e:
        print("ERR", page, e)
        break

print("\ncollected:", len(items))

# Verify each disclosure page
verified = []
for it in items:
    url = "https://bugcrowd.com" + it["disclosure_report_url"]
    try:
        r = requests.get(url, headers=H, timeout=30, allow_redirects=True)
        ok = r.status_code == 200 and "CrowdStream - Bugcrowd" in r.text and len(r.text) > 20000
        if ok:
            verified.append({
                "url": url,
                "title": it.get("title", ""),
                "program": it.get("engagement_name", ""),
                "target": it.get("target", ""),
                "researcher": it.get("researcher_username", ""),
                "priority": it.get("priority"),
                "disclosed_at": it.get("disclosed_at", ""),
            })
        print(("OK " if ok else "FAIL "), it.get("title", "")[:50])
    except Exception as e:
        print("ERR", url, e)
    time.sleep(0.3)

print("\nVERIFIED:", len(verified))
with open("learningfromreport/bugcrowd_verified.json", "w", encoding="utf-8") as f:
    json.dump(verified, f, indent=1)
with open("learningfromreport/bugcrowd_verified.csv", "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(verified[0].keys()) if verified else ["url"])
    w.writeheader()
    w.writerows(verified)
for v in verified:
    print(v["url"], "|", v["title"][:60], "|", v["program"], "| P" + str(v["priority"]))
