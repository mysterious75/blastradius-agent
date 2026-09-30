"""Verify Umbrella StakeToken addresses on-chain (totalAssets + decimals)."""
import json
import urllib.request
import ssl
import time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
RPC = "https://ethereum-rpc.publicnode.com"

TOKENS = {
    "stkwaUSDC": "0x6bf183243FdD1e306ad2C4450BC7dcf6f0bf8Aa6",
    "stkwaUSDT": "0xA484Ab92fe32B143AEE7019fC1502b1dAA522D31",
    "stkwaWETH": "0xaAFD07D53A7365D3e9fb6F3a3B09EC19676B73Ce",
    "stkGHO": "0x4f827A63755855cDf3e8f3bcD20265C833f15033",
}
# totalAssets() 0x01e1d114, decimals() 0x313ce567, asset() 0x38d52e0f
CALLS = {"totalAssets": "01e1d114", "decimals": "313ce567", "asset": "38d52e0f"}


def eth_call(to_addr, data):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                       "params": [{"to": to_addr, "data": "0x" + data}, "latest"]}).encode()
    req = urllib.request.Request(RPC, data=body,
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.loads(r.read().decode())


for name, addr in TOKENS.items():
    out = {}
    for label, sel in CALLS.items():
        try:
            res = eth_call(addr, sel)
            out[label] = res.get("result", "")[:66] if isinstance(res, dict) else str(res)[:60]
        except Exception as e:
            out[label] = f"ERR {str(e)[:50]}"
        time.sleep(0.4)
    print(name, addr)
    for k, v in out.items():
        print(f"   {k}: {v}")
