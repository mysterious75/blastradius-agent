"""Dynamic benchmark target: live-massassign.

  POST /api/profile  mass-assigns the whole body (vuln: persists role=...)
  POST /api/strict   allowlists name only (safe control)
  GET  /api/me       returns the stored object (persistence oracle)

Ground truth: one HIGH massassign on /api/profile, nothing on /api/strict.
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
import json
import urllib.parse

STORE = {"name": "bob"}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if urllib.parse.urlparse(self.path).path == "/api/me":
            return self._send(200, json.dumps(STORE).encode())
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:
            body = {}
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/profile":
            STORE.update(body)
            return self._send(200, json.dumps(STORE).encode())
        if path == "/api/strict":
            STORE["name"] = body.get("name", STORE["name"])
            return self._send(200, json.dumps({"name": STORE["name"]}).encode())
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
