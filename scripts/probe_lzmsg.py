"""Fetch one full Scan API message to map the config shape."""

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
print("tx:", tx)
msg = get(f"https://scan.layerzero-api.com/v1/messages/tx/{tx}")
print("top keys:", list(msg.keys()))
# find config blocks
s = json.dumps(msg)
for key in [
    "requiredDVNs",
    "optionalDVNs",
    "optionalDVNThreshold",
    "requiredDVNCount",
    "optionalDVNCount",
    "confirmations",
    "executor",
    "sendLibrary",
    "receiveLibrary",
    "verification",
    "config",
]:
    print(f"  {key}: {s.count(chr(34) + key + chr(34))} occurrence(s)")
# print one config-ish subtree
data = msg.get("data", msg)
print("\ndata keys:", list(data.keys()) if isinstance(data, dict) else type(data))
