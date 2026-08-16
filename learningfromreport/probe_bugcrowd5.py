import requests

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
for f in ["paths-R3FKsrba.js", "dist-CUAJiqlC.js", "queryKeys-DJ1hi3L2.js", "useOverviewData-CVcIJYIp.js"]:
    js = requests.get("https://bugcrowd.com/h/assets/" + f, headers=H, timeout=60).text
    print(f"===== {f} =====")
    print(js[:3000])
    print()
