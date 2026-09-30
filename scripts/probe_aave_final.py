"""Final verified Aave reserves query."""
import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"

q = """{ markets(request: {chainIds: [1]}) {
  name address chain { chainId }
  reserves {
    underlyingToken { symbol address }
    usdOracleAddress
    isPaused isFrozen
    supplyInfo { maxLTV { value } liquidationThreshold { value } liquidationBonus { value } canBeCollateral supplyCap { amount { value } } }
    eModeInfo { categoryId label }
  }
} }"""
body = json.dumps({"query": q}).encode()
req = urllib.request.Request("https://api.v3.aave.com/graphql", data=body,
                             headers={"User-Agent": UA, "Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
    d = json.loads(r.read().decode())
if "errors" in d:
    print("ERRORS:", json.dumps(d["errors"])[:800])
else:
    ms = d["data"]["markets"]
    print("markets:", [(m["name"], len(m["reserves"])) for m in ms])
    print(json.dumps(ms[0]["reserves"][1], indent=1)[:900])
    open(r"D:\deepseek\blastradius-agent\data\ingest\aave_reserves_eth.json", "w").write(json.dumps(d, indent=1))
    print("saved sample")
