"""Download the keyless DeFi dependency-graph data sources into data/ingest/.
Read-only public APIs, rate-limited, identifying UA. Prints sizes.
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"
OUT = r"D:\deepseek\blastradius-agent\data\ingest"
os.makedirs(OUT, exist_ok=True)

TARGETS = [
    ("defillama_protocols.json", "https://api.llama.fi/protocols"),
    ("defillama_pools.json", "https://yields.llama.fi/pools"),
    ("defillama_lendborrow.json", "https://yields.llama.fi/lendBorrow"),
    (
        "chainlink_feeds_mainnet.json",
        "https://reference-data-directory.vercel.app/feeds-mainnet.json",
    ),
    (
        "chainlink_feeds_arbitrum.json",
        "https://reference-data-directory.vercel.app/feeds-arbitrum-mainnet.json",
    ),
    (
        "chainlink_feeds_base.json",
        "https://reference-data-directory.vercel.app/feeds-base-mainnet.json",
    ),
    (
        "chainlink_feeds_optimism.json",
        "https://reference-data-directory.vercel.app/feeds-optimism-mainnet.json",
    ),
    ("pyth_price_feeds.json", "https://hermes.pyth.network/v2/price_feeds?asset_type=crypto"),
    ("layerzero_metadata.json", "https://metadata.layerzero-api.com/v1/metadata"),
    ("morpho_blue_markets.json", "https://api.morpho.org/v1/blue/markets"),
    ("fluid_vaults_eth.json", "https://api.fluid.instadapp.io/v2/borrowing/1/vaults"),
    ("chainid_chains.json", "https://chainid.network/chains.json"),
]

for fname, url in TARGETS:
    path = os.path.join(OUT, fname)
    if os.path.exists(path) and os.path.getsize(path) > 100:
        print(f"[skip] {fname} exists ({os.path.getsize(path)} bytes)")
        continue
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=90, context=ctx) as r:
            data = r.read()
        # validate JSON then save
        json.loads(data.decode("utf-8"))
        with open(path, "wb") as f:
            f.write(data)
        print(f"[ok]   {fname}  {len(data)} bytes")
    except Exception as e:  # noqa: BLE001 - diagnostic script must report, never crash
        print(f"[FAIL] {fname}  {str(e)[:70]}")
    time.sleep(0.5)
