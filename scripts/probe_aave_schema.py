"""Introspect Aave GraphQL schema for exact field names."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"

q = """{ __type(name: "TokenAmount") { fields { name } } }"""
body = json.dumps({"query": q}).encode()
req = urllib.request.Request(
    "https://api.v3.aave.com/graphql",
    data=body,
    headers={"User-Agent": UA, "Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
    d = json.loads(r.read().decode())
print(
    "TokenAmount:", [f["name"] for f in (d.get("data") or {}).get("__type", {}).get("fields", [])]
)

for t in ["ReserveBorrowInfo", "Reserve", "ReserveSupplyInfo"]:
    q = '{ __type(name: "%s") { fields { name } } }' % t
    body = json.dumps({"query": q}).encode()
    req = urllib.request.Request(
        "https://api.v3.aave.com/graphql",
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        d = json.loads(r.read().decode())
    print(t, ":", [f["name"] for f in (d.get("data") or {}).get("__type", {}).get("fields", [])])
