"""Live demo target for cache-poisoning checks (stdlib only).

  /page     reflects X-Forwarded-Host into a <script src> and caches publicly
            (vulnerable: unkeyed header + persistence)
  /safe     ignores extra headers, no-store (safe control)
  /account  serves HTML under any path incl. .css suffix, cacheable (WCD-ish)

Usage: python demos/cachepoison_demo_server.py [port]   # default 8096
"""

import http.server
import sys
import urllib.parse

CACHE = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, headers=None):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        host = self.headers.get("X-Forwarded-Host", "")
        if parsed.path == "/page":
            key = self.path.split("?")[0] + "|page"
            if key in CACHE:
                body, hdrs = CACHE[key]
                self._send(200, body, {**hdrs, "Age": "12"})
                return
            if host:
                body = f'<html><script src="//{host}/x.js"></script></html>'
            else:
                body = "<html>clean</html>"
            CACHE[key] = (body, {"Cache-Control": "public, max-age=3600"})
            self._send(200, body, {"Cache-Control": "public, max-age=3600"})
            return
        if parsed.path == "/safe":
            self._send(200, "<html>clean</html>", {"Cache-Control": "no-store"})
            return
        if parsed.path.startswith("/account"):
            self._send(
                200,
                "<html>user-profile</html>",
                {"Content-Type": "text/html", "Cache-Control": "public, max-age=600"},
            )
            return
        if parsed.path == "/":
            self._send(200, b"<html><body>cache demo</body></html>", {"Content-Type": "text/html"})
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8096
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
