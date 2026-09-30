"""Probe keyless DeFi data sources for live availability (HEAD/GET small), report status.
No writes. Prints reachability so we know what is safe to download in bulk.
"""

import ssl
import urllib.error
import urllib.request

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

UA = "blastradius-contagion/0.1 (+https://github.com/mysterious75/blastradius-agent)"

SOURCES = [
    ("defillama protocols", "https://api.llama.fi/protocols"),
    ("defillama yields pools", "https://yields.llama.fi/pools"),
    ("defillama lendBorrow", "https://yields.llama.fi/lendBorrow"),
    ("chainlink feeds mainnet", "https://reference-data-directory.vercel.app/feeds-mainnet.json"),
    (
        "chainlink feeds ethereum",
        "https://reference-data-directory.vercel.app/feeds-ethereum-mainnet.json",
    ),
    (
        "chainlink feeds arbitrum",
        "https://reference-data-directory.vercel.app/feeds-arbitrum-mainnet.json",
    ),
    ("pyth price feeds", "https://hermes.pyth.network/v2/price_feeds?asset_type=crypto"),
    ("layerzero metadata", "https://metadata.layerzero-api.com/v1/metadata"),
    ("layerzero scan base", "https://scan.layerzero-api.com/v1/messages/latest"),
    ("morpho markets", "https://api.morpho.org/v1/blue/markets"),
    ("aave v3 graphql", "https://api.v3.aave.com/graphql"),
    ("fluid vaults eth", "https://api.fluid.instadapp.io/v2/borrowing/1/vaults"),
    ("chainid network", "https://chainid.network/chains.json"),
    ("lido steth price", "https://eth-api.lido.fi/v1/protocol/steth/price"),
    ("oanor lrt rates", "https://www.oanor.com/api/lrtcompare-api/v1/rates"),
]

for name, url in SOURCES:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            data = r.read(3000)
            print(f"[{r.status}] {name:32} {url[:60]}  bytes~{len(data)}")
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] {name:32} {url[:60]}  {str(e.reason)[:40]}")
    except Exception as e:  # noqa: BLE001 - diagnostic script must report, never crash
        print(f"[ERR] {name:32} {url[:60]}  {str(e)[:50]}")
