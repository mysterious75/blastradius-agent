import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"}
# wayback crowdstream HTML from 2021 to see link format to disclosures
r = requests.get("https://web.archive.org/web/20210325200258id_/https://bugcrowd.com/crowdstream", headers=H, timeout=90)
t = r.text
print("len", len(t))
links = set(re.findall(r'href="([^"]*vulnerab[^"]*)"', t))
for l in sorted(links)[:40]:
    print(l)
# also look for report links
links2 = set(re.findall(r'href="([^"]*(?:/r|reports?|/v/)[^"]*)"', t))
for l in sorted(links2)[:40]:
    print("R:", l)
