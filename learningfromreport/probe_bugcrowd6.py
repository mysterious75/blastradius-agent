import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

# Fetch the actual vuln page HTML and look for embedded JSON / route data
html = requests.get("https://bugcrowd.com/h/vulnerability/2911", headers=H, timeout=30).text
print("--- page meta ---")
for m in re.findall(r'<meta[^>]+>', html)[:10]:
    print(m)
print("--- script modulepreload / any data json ---")
for m in re.findall(r'<script[^>]*src="([^"]+)"', html):
    print(m)

# Look at index bundle for dynamic import chunk mapping
js = requests.get("https://bugcrowd.com/h/assets/index-CFKKCs0y.js", headers=H, timeout=120).text
# find import() statements referencing chunk names
imps = re.findall(r'import\(["\']([^"\']+\.js)["\']\)', js)
print("\n--- dynamic imports in index ---")
for i in sorted(set(imps))[:40]:
    print(i)
# look for vulnerability strings in chunk-62JRHF6Z and build
for f in ["chunk-62JRHF6Z-DHccZF4d.js", "index-CFKKCs0y.js"]:
    js2 = requests.get("https://bugcrowd.com/h/assets/" + f, headers=H, timeout=120).text
    for kw in ["vulnerability-service", "/vulnerability/", "disclosure", "vulnerabilities"]:
        c = js2.count(kw)
        if c:
            print(f"{f}: '{kw}' x{c}")
