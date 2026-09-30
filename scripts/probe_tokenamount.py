"""Introspect TokenAmount sub-fields."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

q = '{ __type(name:"TokenAmount") { fields { name type { name kind ofType { name } } } } }'
body = json.dumps({"query": q}).encode()
req = urllib.request.Request(
    "https://api.v3.aave.com/graphql",
    data=body,
    headers={"User-Agent": "br/1.0", "Content-Type": "application/json"},
)
d = json.loads(urllib.request.urlopen(req, timeout=30, context=ctx).read().decode())
for f in d["data"]["__type"]["fields"]:
    print(f["name"], "->", f["type"])
