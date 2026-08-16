import urllib.request, os, zipfile, time

UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0'}
DST = r"D:\vora\New folder\mycli\blastradius-agent\reports5000"
ZIP = os.path.join(DST, "advisory-database-main.zip")

url = "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"
print("downloading", url)
t0 = time.time()
req = urllib.request.Request(url, headers=UA)
with urllib.request.urlopen(req, timeout=300) as r, open(ZIP, "wb") as f:
    total = 0
    while True:
        chunk = r.read(1 << 20)
        if not chunk:
            break
        f.write(chunk)
        total += len(chunk)
print(f"downloaded {total/1e6:.1f} MB in {time.time()-t0:.0f}s -> {ZIP}")

EXTRACT = os.path.join(DST, "ghsa_repo")
os.makedirs(EXTRACT, exist_ok=True)
with zipfile.ZipFile(ZIP) as z:
    z.extractall(EXTRACT)
print("extracted to", EXTRACT)

# count reviewed advisories
root = os.path.join(EXTRACT, "advisory-database-main", "advisories", "github-reviewed")
n = 0
for dp, dn, fn in os.walk(root):
    n += sum(1 for f in fn if f.endswith(".json"))
print("github-reviewed json files:", n)
