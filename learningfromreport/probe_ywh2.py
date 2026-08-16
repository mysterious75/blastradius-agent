import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"}
for u in [
    "https://www.yeswehack.com/sitemap.xml",
    "https://www.yeswehack.com/robots.txt",
    "https://docs.yeswehack.com/api-reference",
]:
    try:
        r = requests.get(u, headers=H, timeout=30)
        print(r.status_code, "len", len(r.text), "->", u)
        if r.status_code == 200:
            print("   ", r.text[:400].replace("\n", " "))
    except Exception as e:
        print("ERR", u, str(e)[:80])
