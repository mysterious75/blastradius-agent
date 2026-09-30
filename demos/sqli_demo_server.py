"""Live demo targets for SQLi + mass-assignment checks (stdlib only).

  GET /search?q=     error-based SQLi when q contains a quote (simulated)
  GET /items?id=     boolean-differential SQLi (different bodies for 1=1/1=2)
  GET /safe?q=       parameterized control (identical bodies, no error)
  POST /api/profile  mass-assignment vuln (echoes + persists privileged fields)
  POST /api/strict   strict control (strips unknown fields)

Usage: python demos/sqli_demo_server.py [port]   # default 8095
"""
import http.server
import json
import sys
import urllib.parse

STORE = {"name": "bob"}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/search":
            q = qs.get("q", [""])[0]
            if "'" in q or '"' in q:
                return self._send(
                    200, b'{"error":"You have an error in your SQL syntax near \'%s\'"' % q.encode()[:20])
            return self._send(200, b'{"results":[]}')
        if parsed.path == "/items":
            ident = qs.get("id", [""])[0]
            if "1=1" in ident:
                return self._send(200, b'{"items":["a","b","c","d"]}')
            return self._send(200, b'{"items":[]}')
        if parsed.path == "/safe":
            return self._send(200, b'{"results":[]}')
        if parsed.path == "/api/me":
            return self._send(200, json.dumps(STORE).encode())
        if parsed.path == "/":
            return self._send(200, b"<html><body>sqli demo</body></html>", "text/html")
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception:  # noqa: BLE001 - demo server must not crash on bad input
            body = {}
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/profile":
            STORE.update(body)  # VULN: mass assignment
            return self._send(200, json.dumps(STORE).encode())
        if path == "/api/strict":
            STORE["name"] = body.get("name", STORE["name"])  # allowlist
            return self._send(200, json.dumps({"name": STORE["name"]}).encode())
        if path == "/api/me":
            return self._send(200, json.dumps(STORE).encode())
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
