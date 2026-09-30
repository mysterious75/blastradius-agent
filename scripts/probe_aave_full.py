"""Probe fuller reserve shape: oracle, caps, isolation, borrow info."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"

q = """{ markets(request: {chainIds: [1]}) {
  name
  reserves {
    underlyingToken { symbol address }
    supplyInfo { maxLTV { value } liquidationThreshold { value } liquidationBonus { value } canBeCollateral supplyCap { value } }
    borrowInfo { canBeBorrowed }
    isolationModeConfig { debtCeiling { value } }
    priceOracle { address }
    isPaused isFrozen isActive
  }
} }"""
body = json.dumps({"query": q}).encode()
req = urllib.request.Request(
    "https://api.v3.aave.com/graphql",
    data=body,
    headers={"User-Agent": UA, "Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
    d = json.loads(r.read().decode())
if "errors" in d:
    print("ERRORS:", json.dumps(d["errors"])[:1500])
else:
    ms = d["data"]["markets"]
    print("markets:", [(m["name"], len(m.get("reserves", []))) for m in ms])
    print("\nsample reserve keys:", list(ms[0]["reserves"][0].keys()))
    print(json.dumps(ms[0]["reserves"][0], indent=1)[:1500])
