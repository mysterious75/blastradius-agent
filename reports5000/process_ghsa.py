"""Download + process the GitHub Advisory Database (GHSA) -> compact corpus."""
import json
import time
import urllib.request
import zipfile
from pathlib import Path

DST = Path("reports5000")
ZIP = DST / "ghsa.zip"
URL = "https://codeload.github.com/github/advisory-database/zip/refs/heads/main"

if not ZIP.exists() or ZIP.stat().st_size < 10_000_000:
    print(f"downloading {URL}")
    t0 = time.time()
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=600) as r, open(ZIP, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    print(f"downloaded {ZIP.stat().st_size/1e6:.1f} MB in {time.time()-t0:.0f}s")

with zipfile.ZipFile(ZIP) as z:
    names = [
        n for n in z.namelist()
        if n.startswith("advisory-database-main/advisories/github-reviewed/")
        and n.endswith(".json")
    ]
    print("github-reviewed advisory json files:", len(names))
    corpus = []
    for n in names:
        try:
            d = json.loads(z.read(n))
        except Exception:
            continue
        sev = (d.get("database_specific") or {}).get("severity", "")
        corpus.append({
            "id": d.get("id"),
            "aliases": d.get("aliases", [])[:3],
            "summary": d.get("summary", "")[:300],
            "severity": sev,
            "published": d.get("published", ""),
            "references": [r.get("url") for r in d.get("references", []) if r.get("url")][:5],
        })

    (DST / "ghsa_corpus.json").write_text(
        json.dumps({"count": len(corpus), "advisories": corpus}, indent=1),
        encoding="utf-8",
    )
    print(f"wrote {DST / 'ghsa_corpus.json'} with {len(corpus)} advisories")
