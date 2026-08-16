import requests, json

H = {"User-Agent": "Mozilla/5.0"}
queries = [
    "bugcrowd.com/shopify/disclosures",
    "bugcrowd.com/disclosures",
    "bugcrowd.com/vulnerabilities*",
]
for q in queries:
    url = ("http://web.archive.org/cdx/search/cdx?url=" + q +
           "&output=json&limit=12&fl=original,timestamp,statuscode")
    try:
        r = requests.get(url, headers=H, timeout=120)
        rows = json.loads(r.text)
        print("== ", q, "->", len(rows) - 1, "rows")
        for row in rows[1:13]:
            print("   ", row)
    except Exception as e:
        print("== ", q, "ERR", e)
