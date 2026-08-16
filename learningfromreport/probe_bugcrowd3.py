import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
html = requests.get("https://bugcrowd.com/h/vulnerability/2911", headers=H, timeout=30).text
print("=== HTML refs ===")
for m in sorted(set(re.findall(r'(?:src|href)="([^"]+)"', html))):
    print(m)

js = requests.get("https://bugcrowd.com/h/assets/index-CFKKCs0y.js", headers=H, timeout=120).text
print("\n=== .js references in bundle ===")
for m in sorted(set(re.findall(r'["\']([^"\']*\.js(?:[^"\']*))["\']', js)))[:30]:
    print(m)
print("\n=== fetch/XMLHttpRequest usage ===")
for m in re.findall(r'fetch\([^)]{0,120}', js)[:20]:
    print(m)
