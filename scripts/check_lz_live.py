"""Live cross-check: real Scan message -> pathways -> audit report."""

import json
import sys
import urllib.request
import ssl

sys.path.insert(0, r"D:\deepseek\blastradius-agent")
from blastradius.contagion.config_audit import ConfigAuditor
from blastradius.contagion.loaders import layerzero

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
msgs = layerzero.fetch_message(tx)
print("messages:", len(msgs))

meta = json.load(
    open(r"D:\deepseek\blastradius-agent\data\ingest\layerzero_metadata.json", encoding="utf-8")
)
reg = layerzero.load_dvn_registry(meta)
print("registry operators:", len(reg))

snap = layerzero.build_audit_snapshot(msgs, reg, target=f"live:{tx[:10]}")
print("pathways:", len(snap["pathways"]))
report = ConfigAuditor().audit(snap)
print("worst:", report.worst_severity, "| counts:", report.counts())
for f in report.sorted_findings()[:8]:
    print(f"  [{f.severity}] {f.rule_id} {f.target} :: {f.title[:70]}")
