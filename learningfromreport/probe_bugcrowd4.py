import requests, re

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
files = ["paths-R3FKsrba.js", "useOverviewData-CVcIJYIp.js", "build-Bd7yK7DP.js",
         "dist-BaHQczPt.js", "dist-BuLPQ6cM.js", "dist-CUAJiqlC.js", "queryKeys-DJ1hi3L2.js"]

for f in files:
    js = requests.get("https://bugcrowd.com/h/assets/" + f, headers=H, timeout=60).text
    print(f"\n===== {f} len={len(js)} =====")
    for kw in ["vulnerab", "disclos", "reports", "/api", "graphql", "csr_", "csrf"]:
        idxs = [m.start() for m in re.finditer(kw, js, re.I)]
        if idxs:
            print(f"  '{kw}': {len(idxs)}x")
            for i in idxs[:5]:
                print("    ...", js[max(0,i-70):i+110].replace("\n"," ")[:180])
