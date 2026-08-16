import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
js = requests.get("https://bugcrowd.com/h/assets/index-CFKKCs0y.js", headers=H, timeout=120).text
print("js len:", len(js))

# search for interesting strings
for kw in ["graphql", "api.", "/api/", "vulnerability/", "disclosures", "public_reports", "reports/"]:
    idxs = [m.start() for m in re.finditer(re.escape(kw), js)]
    print(f"\n--- '{kw}': {len(idxs)} occurrences ---")
    for i in idxs[:6]:
        print("   ...", js[max(0,i-80):i+120].replace("\n"," ")[:200])

# dynamic import chunks
chunks = sorted(set(re.findall(r'["\']([A-Za-z0-9_\-]+-[A-Za-z0-9_\-]+\.js)["\']', js)))
print("\nchunk files referenced:", len(chunks))
print(chunks[:40])
