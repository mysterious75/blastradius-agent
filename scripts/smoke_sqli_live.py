"""Live end-to-end smoke test: SQLi + mass-assignment checks vs demo servers."""
import http.server
import importlib.util
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
spec = importlib.util.spec_from_file_location(
    "sqli_demo", r"D:\deepseek\blastradius-agent\demos\sqli_demo_server.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

srv = http.server.HTTPServer(("127.0.0.1", 8095), demo.Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.5)

from blastradius.web.massassign import MassassignChecker
from blastradius.web.sqli import SqliChecker

ok = True

# 1. error-based SQLi fires, safe control does not
hits = SqliChecker().check(["http://127.0.0.1:8095/search?q=x",
                            "http://127.0.0.1:8095/safe?q=x"])
kinds = {(h.url.split("?")[0].rsplit("/", 1)[-1], h.check) for h in hits}
print("sqli hits:", kinds)
ok &= ("search", "sqli-error") in kinds and not any(k[0] == "safe" for k in kinds)

# 2. boolean differential fires on /items
hits = SqliChecker().check(["http://127.0.0.1:8095/items?id=1"])
print("bool hits:", [(h.check, h.confidence) for h in hits])
ok &= any(h.check == "sqli-boolean" for h in hits)

# 3. mass assignment persists on /api/profile, not on /api/strict
hits = MassassignChecker(verify_url="http://127.0.0.1:8095/api/me").check(
    "http://127.0.0.1:8095/api/profile", {"name": "bob"})
print("massassign vuln:", [(h.severity) for h in hits][:3])
ok &= any(h.severity == "HIGH" for h in hits)
hits = MassassignChecker().check("http://127.0.0.1:8095/api/strict", {"name": "bob"})
print("massassign strict hits:", len(hits))
ok &= len(hits) == 0

srv.shutdown()
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
