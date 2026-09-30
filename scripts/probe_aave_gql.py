"""Probe Aave V3 GraphQL API shape: markets + reserves with collateral flags."""
import json
import sys
import urllib.request
import urllib.error
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
URL = "https://api.v3.aave.com/graphql"


def gql(query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(URL, data=body, headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read().decode())


# 1. minimal markets
q1 = "{ markets(request: {chainIds: [1]}) { name chain { chainId } address } }"
try:
    d = gql(q1)
    print("markets:", json.dumps(d)[:400])
except Exception as e:
    print("q1 ERR", str(e)[:200])

# 2. reserves with collateral flags
q2 = """{ markets(request: {chainIds: [1]}) {
  name address
  reserves { underlyingToken { symbol address } supplyInfo { maxLTV { value } liquidationThreshold { value } canBeCollateral } }
} }"""
try:
    d = gql(q2)
    m = (d.get("data") or {}).get("markets") or []
    print("\nmarkets count:", len(m))
    if m:
        r0 = (m[0].get("reserves") or [])[:3]
        print(json.dumps(r0, indent=1)[:1200])
    if "errors" in d:
        print("ERRORS:", json.dumps(d["errors"])[:800])
except Exception as e:
    print("q2 ERR", str(e)[:200])
