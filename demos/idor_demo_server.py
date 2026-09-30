"""Live demo target for the authz-diff (IDOR) check — stdlib only.

Two object endpoints:
  /api/user/<id>   returns the user's email (IDOR: any session can read any id)
  /api/safe/<id>   returns the caller's own data only (ownership enforced)

Identity comes from the `X-Identity` header (A or B). The IDOR endpoint ignores
it; the safe endpoint honours it. Proves the check flags the first and not the
second, live.

Usage:
    python demos/idor_demo_server.py            # http://127.0.0.1:8091
    # then:
    python -m blastradius.web --target http://127.0.0.1:8091 \
        --attacker-cookie "x=1" --victim-cookie "x=1"
"""
import http.server
import sys
import urllib.parse

USERS = {"1": "alice@corp.test", "2": "victim@corp.test", "3": "carol@corp.test"}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # identity from a custom header (a real app would use the session cookie)
        ident = self.headers.get("X-Identity", "A")
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "user":
            uid = parts[2]
            email = USERS.get(uid)
            if email is None:
                return self._send(404, b'{"error":"not found"}')
            # IDOR: no ownership check
            return self._send(200, f'{{"id":"{uid}","email":"{email}"}}'.encode())
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "safe":
            uid = parts[2]
            # ownership enforced: caller may only read their own id
            myid = "2" if ident == "B" else "1"
            if uid != myid:
                return self._send(403, b'{"error":"forbidden"}')
            return self._send(200, f'{{"id":"{uid}","email":"{USERS[uid]}"}}'.encode())
        if path == "/":
            return self._send(200, b"<html><body>idor demo</body></html>", "text/html")
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
