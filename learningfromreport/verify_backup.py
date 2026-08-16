import json, time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

ids = sys_argv_ids = json.load(open("learningfromreport/candidates.json", encoding="utf-8"))
ids = [c[0] for c in ids[95:120]]

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

def fetch(rid):
    url = f"https://hackerone.com/reports/{rid}.json"
    for attempt in range(2):
        try:
            r = requests.get(url, headers=H, timeout=30)
            if r.status_code == 200:
                j = r.json()
                info = j.get("vulnerability_information", "")
                return {"id": rid, "http": 200, "title": j.get("title", ""),
                        "has_info": bool(info), "info_len": len(info or "")}
            if r.status_code == 404:
                return {"id": rid, "http": 404}
            time.sleep(2.5 * (attempt + 1))
        except Exception:
            time.sleep(2)
    return {"id": rid, "http": 0}

results = []
with ThreadPoolExecutor(max_workers=6) as ex:
    futs = {ex.submit(fetch, rid): rid for rid in ids}
    for fut in as_completed(futs):
        results.append(fut.result())
results.sort(key=lambda r: ids.index(r["id"]))
json.dump(results, open("learningfromreport/verified_backup.json", "w", encoding="utf-8"), indent=1)
ok = [r["id"] for r in results if r.get("has_info")]
print("backup verified info=yes:", len(ok))
print(",".join(ok))
