import json, time, csv, io, sys, re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

cands = json.load(open("learningfromreport/candidates.json", encoding="utf-8"))
ids = [c[0] for c in cands[:95]]

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

def fetch(rid):
    url = f"https://hackerone.com/reports/{rid}.json"
    for attempt in range(2):
        try:
            r = requests.get(url, headers=H, timeout=30)
            if r.status_code == 200:
                j = r.json()
                info = j.get("vulnerability_information", "")
                return {
                    "id": rid,
                    "http": r.status_code,
                    "title": j.get("title", ""),
                    "team": j.get("team", {}).get("handle", "") if isinstance(j.get("team"), dict) else str(j.get("team", "")),
                    "visibility": j.get("visibility", ""),
                    "state": j.get("state", ""),
                    "has_info": bool(info),
                    "info_len": len(info or ""),
                }
            if r.status_code == 404:
                return {"id": rid, "http": 404, "error": "not_found"}
            if r.status_code in (429, 403, 500, 502, 503):
                time.sleep(2.5 * (attempt + 1))
                continue
            return {"id": rid, "http": r.status_code, "error": r.text[:100]}
        except Exception as e:
            time.sleep(2)
    return {"id": rid, "http": 0, "error": "exception"}

results = []
with ThreadPoolExecutor(max_workers=6) as ex:
    futs = {ex.submit(fetch, rid): rid for rid in ids}
    for i, fut in enumerate(as_completed(futs), 1):
        res = fut.result()
        results.append(res)
        if i % 10 == 0:
            ok = sum(1 for r in results if r.get("has_info"))
            print(f"...{i}/{len(ids)} done, info=yes so far: {ok}", flush=True)

results.sort(key=lambda r: ids.index(r["id"]))
json.dump(results, open("learningfromreport/verified.json", "w", encoding="utf-8"), indent=1)
ok = [r for r in results if r.get("has_info")]
print("\n=== SUMMARY ===")
print("fetched:", len(results), "| info=yes:", len(ok))
print("\nVerified IDs:")
print(",".join(r["id"] for r in ok))
