"""Real-target proof: scan our OWN dashboard + API locally with our dynamic scanner."""

import sys
import threading
import time

sys.path.insert(0, r"D:\deepseek\blastradius-agent")
import uvicorn
from blastradius.dashboard.app import app as dash_app  # noqa: E402 - sys.path bootstrap above

t1 = threading.Thread(
    target=uvicorn.run,
    kwargs={"app": dash_app, "host": "127.0.0.1", "port": 8097, "log_level": "error"},
    daemon=True,
)
t1.start()
time.sleep(2.0)

from blastradius.web.cli import main  # noqa: E402 - sys.path bootstrap above

print("===== own dashboard :8097 =====")
rc1 = main(["--target", "http://127.0.0.1:8097", "--max-urls", "8"])
print("dashboard rc=", rc1)
