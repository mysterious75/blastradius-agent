import requests, json

H = {"User-Agent": "Mozilla/5.0"}
queries = [
    "www.bugcrowd.com/vulnerabilities/",
    "bugcrowd.com/vulnerabilities/",
    "www.bugcrowd.com/vulnerability/",
    "bugcrowd.com/crowdstream",
]
for q in queries:
    url = ("http://web.archive.org/cdx/search/cdx?url=" + q +
           "&output=json&matchType=prefix&limit=15&fl=original,timestamp,statuscode")
    try:
        r = requests.get(url, headers=H, timeout=120)
        rows = json.loads(r.text)
        print("== ", q, "->", len(rows) - 1, "rows")
        for row in rows[1:16]:
            print("   ", row)
    except Exception as e:
        print("== ", q, "ERR", e)
