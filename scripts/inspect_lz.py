"""Inspect LayerZero metadata shapes (offline, downloaded data)."""

import json

m = json.load(
    open(r"D:\deepseek\blastradius-agent\data\ingest\layerzero_metadata.json", encoding="utf-8")
)
e = m["ethereum"]
deps = e.get("deployments") or []
print("deployments type:", type(deps), "count:", len(deps) if isinstance(deps, list) else "?")
if isinstance(deps, list) and deps:
    print("dep[0] keys:", list(deps[0].keys())[:20])
    print(json.dumps(deps[0], ensure_ascii=False)[:600])
d = e.get("dvns")
print("\ndvns type:", type(d))
if isinstance(d, dict):
    k = list(d.keys())[0]
    print("dvn key:", k, json.dumps(d[k], ensure_ascii=False)[:400])
elif isinstance(d, list) and d:
    print(json.dumps(d[0], ensure_ascii=False)[:500])
toks = e.get("tokens")
print("\ntokens type:", type(toks))
if isinstance(toks, dict):
    k = list(toks.keys())[0]
    print("token key:", k, json.dumps(toks[k], ensure_ascii=False)[:400])
elif isinstance(toks, list) and toks:
    print(json.dumps(toks[0], ensure_ascii=False)[:500])
