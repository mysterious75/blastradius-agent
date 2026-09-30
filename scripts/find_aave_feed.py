"""Find AAVE/USD feed in the downloaded Chainlink registry."""

import json

feeds = json.load(
    open(
        r"D:\deepseek\blastradius-agent\data\ingest\chainlink_feeds_mainnet.json", encoding="utf-8"
    )
)
print(type(feeds), len(feeds) if hasattr(feeds, "__len__") else "?")
items = feeds if isinstance(feeds, list) else feeds.get("feeds", [])
print("sample:", json.dumps(items[0], ensure_ascii=False)[:300])
for f in items:
    if not isinstance(f, dict):
        continue
    for v in f.values():
        if isinstance(v, str) and "AAVE" in v.upper() and "USD" in v.upper():
            print("HIT:", json.dumps(f, ensure_ascii=False)[:300])
            break
