"""Dump one Scan API message config subtree (exact field paths)."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode())


latest = get("https://scan.layerzero-api.com/v1/messages/latest")
tx = latest["data"][0]["source"]["tx"]["txHash"]
msg = get(f"https://scan.layerzero-api.com/v1/messages/tx/{tx}")
m0 = msg["data"][0]
print("message keys:", list(m0.keys()))
for k in ["config", "verification", "pathway", "source", "destination"]:
    v = m0.get(k)
    if isinstance(v, dict):
        print(f"\n== {k} keys: {list(v.keys())}")
        print(json.dumps(v, ensure_ascii=False)[:1200])
    elif isinstance(v, list):
        print(f"\n== {k} list len {len(v)}")
