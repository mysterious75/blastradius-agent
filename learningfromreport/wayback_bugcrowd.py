import requests, json

H = {"User-Agent": "Mozilla/5.0"}
queries = [
    "bugcrowd.com/vulnerability/",
    "bugcrowd.com/vulnerabilities/",
]
for q in queries:
    url = ("http://web.archive.org/cdx/search/cdx?url=" + q +
           "&output=json&matchType=prefix&limit=30&fl=original,timestamp,statuscode")
    try:
        r = requests.get(url, headers=H, timeout=120)
        rows = json.loads(r.text)
        print("== ", q, "->", len(rows) - 1, "rows")
        for row in rows[1:31]:
            print("   ", row)
    except Exception as e:
        print("== ", q, "ERR", e)
