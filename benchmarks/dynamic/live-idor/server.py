"""Dynamic benchmark target: live-idor.

Two object endpoints; identity comes from the ``X-Identity`` header:
  /api/user/<id>   returns any user's email (IDOR — ignores identity)
  /api/safe/<id>   returns only the caller's own record (ownership enforced)

Ground truth (manifest.json): exactly one ``idor`` hit (on /api/user/2).
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
import urllib.parse

USERS = {"1": "alice@corp.test", "2": "victim@corp.test"}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        ident = self.headers.get("X-Identity", "A")
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "user":
            email = USERS.get(parts[2])
            if email is None:
                return self._send(404, b'{"error":"not found"}')
            return self._send(200, f'{{"id":"{parts[2]}","email":"{email}"}}'.encode())
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "safe":
            myid = "2" if ident == "B" else "1"
            if parts[2] != myid:
                return self._send(403, b'{"error":"forbidden"}')
            return self._send(200, f'{{"id":"{parts[2]}","email":"{USERS[parts[2]]}"}}'.encode())
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
