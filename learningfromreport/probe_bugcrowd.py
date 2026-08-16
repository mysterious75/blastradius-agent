import requests, re, json

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

# get the html shell, then fetch all asset js
html = requests.get("https://bugcrowd.com/h/vulnerability/2911", headers=H, timeout=30).text
assets = re.findall(r'src="(/h/assets/[^"]+\.js)"', html)
print("assets:", assets)
pats = set()
for a in assets:
    js = requests.get("https://bugcrowd.com" + a, headers=H, timeout=60).text
    # look for api base urls and fetch calls
    for m in re.findall(r'["\'](/[^"\']*(?:api|vuln|report|disclos)[^"\']*)["\']', js):
        pats.add(m)
    for m in re.findall(r'["\'](https?://[^"\']*(?:api|vuln|report|disclos)[^"\']*)["\']', js):
        pats.add(m)
out = sorted(pats)
for p in out:
    print(p)
