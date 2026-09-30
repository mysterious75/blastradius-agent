"""Save one live Scan API message as a schema-drift sample (offline tests use it)."""

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
open(r"D:\deepseek\blastradius-agent\data\ingest\lzscan_sample.json", "w").write(
    json.dumps(msg["data"][0], indent=1)
)
print("saved, tx:", tx)
