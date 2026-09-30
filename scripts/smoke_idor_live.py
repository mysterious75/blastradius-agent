"""Live end-to-end smoke test of the authz-diff IDOR check against the demo server."""
import subprocess
import sys
import time
import threading
import http.server
import importlib.util
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# import handler from demo
spec = importlib.util.spec_from_file_location("idor_demo", r"D:\deepseek\blastradius-agent\demos\idor_demo_server.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

srv = http.server.HTTPServer(("127.0.0.1", 8091), demo.Handler)
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
time.sleep(0.5)

from blastradius.web.authz import AuthzDiffChecker
from blastradius.web.browser import BrowserSession

# both sessions are identity A (attacker); victim data belongs to B (id=2)
attacker = BrowserSession(default_headers={"X-Identity": "A"})
victim = BrowserSession(default_headers={"X-Identity": "B"})

c = AuthzDiffChecker(attacker=attacker, victim=victim,
                     victim_markers=["victim@corp.test"])
urls = ["http://127.0.0.1:8091/api/user/2",   # IDOR — should flag
        "http://127.0.0.1:8091/api/safe/2"]   # ownership enforced — should NOT flag
hits = c.check(urls)
print(f"hits: {len(hits)}")
for h in hits:
    print(f"  [{h.severity}] {h.url}  {h.confidence}  {h.evidence[:80]}")
srv.shutdown()

ok = len(hits) == 1 and "api/user/2" in hits[0].url
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
