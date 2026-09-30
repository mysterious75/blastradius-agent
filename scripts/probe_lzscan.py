"""Probe LayerZero Scan API shape (read-only, keyless)."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"

# 1. swagger doc (find message endpoints)
try:
    req = urllib.request.Request(
        "https://scan.layerzero-api.com/v1/swagger",
        headers={"User-Agent": UA, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        print("swagger status:", r.status, "len:", len(r.read()))
except Exception as e:
    print("swagger ERR:", str(e)[:120])

# 2. try a recent message lookup by a well-known OApp (Stargate router) via messages endpoint
for url in [
    "https://scan.layerzero-api.com/v1/messages/latest",
]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
            d = json.loads(r.read().decode())
        print(url, "->", type(d), list(d.keys())[:10] if isinstance(d, dict) else len(d))
        print(json.dumps(d, ensure_ascii=False)[:800])
    except Exception as e:
        print(url, "ERR:", str(e)[:150])
