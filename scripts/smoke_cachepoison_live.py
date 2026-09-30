"""Live end-to-end smoke test: cache-poisoning check vs demo servers."""

import http.server
import importlib.util
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
spec = importlib.util.spec_from_file_location(
    "cp_demo", r"D:\deepseek\blastradius-agent\demos\cachepoison_demo_server.py"
)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

srv = http.server.HTTPServer(("127.0.0.1", 8096), demo.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.4)

from blastradius.web.cachepoison import CachePoisonChecker  # noqa: E402 - server bootstrap above

ok = True
hits = CachePoisonChecker().check(["http://127.0.0.1:8096/page", "http://127.0.0.1:8096/safe"])
kinds = {(h.url.rsplit("/", 1)[-1], h.check, h.severity) for h in hits}
print("hits:", kinds)
ok &= ("page", "cachepoison", "HIGH") in kinds
ok &= not any(k[0] == "safe" for k in kinds)

hits = CachePoisonChecker().check(["http://127.0.0.1:8096/account"])
print("wcd hits:", [(h.severity) for h in hits])
ok &= len(hits) >= 1

srv.shutdown()
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
