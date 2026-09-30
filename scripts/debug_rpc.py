"""Debug raw eth_call shape against public RPCs."""

import json
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

variants = [
    (
        "int-id",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                {"to": "0x4da27a545c0c5B758a264ba8eF45dE6cA23146514", "data": "0x18160ddd"},
                "latest",
            ],
        },
    ),
    (
        "str-id",
        {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "eth_call",
            "params": [
                {"to": "0x4da27a545c0c5B758a264ba8eF45dE6cA23146514", "data": "0x18160ddd"},
                "latest",
            ],
        },
    ),
]
for name, payload in variants:
    body = json.dumps(payload).encode()
    print("body:", body[:120])
    for rpc in [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://eth.drpc.org",
    ]:
        try:
            req = urllib.request.Request(
                rpc, data=body, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
                print(f"  [{name}] {rpc} ->", r.read()[:100])
        except Exception as e:
            print(f"  [{name}] {rpc} ERR:", str(e)[:100])
