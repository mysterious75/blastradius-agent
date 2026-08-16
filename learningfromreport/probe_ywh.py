import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"}
urls = [
    "https://www.yeswehack.com/en/hall-of-fame",
    "https://www.yeswehack.com/en/report/1",
    "https://www.yeswehack.com/en/program/1",
    "https://www.yeswehack.com/api/reports",
    "https://www.yeswehack.com/reports.json",
]
for u in urls:
    try:
        r = requests.get(u, headers=H, timeout=30, allow_redirects=True)
        ct = r.headers.get("content-type", "")
        print(r.status_code, ct[:35], "len", len(r.text), "->", u, "| final:", r.url[:70])
        if "json" in ct:
            print("   BODY:", r.text[:300])
    except Exception as e:
        print("ERR", u, str(e)[:80])

# search yeswehack homepage for report links
r = requests.get("https://www.yeswehack.com/", headers=H, timeout=30)
t = r.text
links = set(re.findall(r'href="([^"]*report[^"]*)"', t, re.I))
print("\nreport links on homepage:", list(links)[:10])
