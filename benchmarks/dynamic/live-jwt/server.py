"""Dynamic benchmark target: live-jwt.

Two verification endpoints (POST form field ``token``):
  /verify   accepts any token whose signature part is empty (alg:none bug)
  /strict   accepts only tokens signed with the server secret (safe control)

Ground truth (manifest.json): exactly one ``jwt-none`` hit (on /verify).
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
import urllib.parse

SECRET = b"bench-secret-12345"


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _token(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        return urllib.parse.parse_qs(body).get("token", [""])[0]

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        token = self._token()
        parts = token.split(".")
        if path == "/verify":
            # VULN: treats an empty signature as valid.
            if len(parts) == 3 and parts[2] == "":
                return self._send(200, b'{"ok":true,"user":"admin"}')
            return self._send(401, b'{"ok":false}')
        if path == "/strict":
            import base64
            import hashlib
            import hmac

            if len(parts) != 3 or not parts[2]:
                return self._send(401, b'{"ok":false}')
            try:
                got = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            except Exception:
                return self._send(401, b'{"ok":false}')
            want = hmac.new(SECRET, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
            if hmac.compare_digest(got, want):
                return self._send(200, b'{"ok":true}')
            return self._send(401, b'{"ok":false}')
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
