"""Probe UmbrellaCore for stake-token registry + read a sample totalAssets via public RPC."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
]


def eth_call(rpc, to_addr, data, tag="latest"):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": to_addr, "data": data}, tag],
        }
    ).encode()
    req = urllib.request.Request(
        rpc, data=body, headers={"User-Agent": UA, "Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


UMBRELLA = "0xD400fc38ED4732893174325693a63C30ee3881a8"
# totalSupply() selector
TOTAL_SUPPLY = "0x18160ddd"

for rpc in RPCS:
    try:
        out = eth_call(rpc, UMBRELLA, TOTAL_SUPPLY)
        print(rpc, "->", json.dumps(out)[:120])
        break
    except Exception as e:
        print(rpc, "ERR:", str(e)[:80])
