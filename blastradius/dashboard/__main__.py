"""python -m blastradius.dashboard — open the dashboard at http://localhost:8080."""

import os
import threading
import webbrowser

import uvicorn

from blastradius.dashboard.app import app


def main() -> int:
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    host = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    url = f"http://localhost:{port}"
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"[*] BlastRadius dashboard at {url} (Ctrl+C to stop)")
    uvicorn.run(app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
