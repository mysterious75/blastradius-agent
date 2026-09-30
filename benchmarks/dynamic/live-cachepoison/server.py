"""Dynamic benchmark target: live-cachepoison.

  /page     reflects X-Forwarded-Host into a <script src> and caches publicly
            (vulnerable: unkeyed header + persistence)
  /safe     ignores extra headers, no-store (safe control)

Ground truth: one HIGH cachepoison on /page, nothing on /safe.
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
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
            key = self.path.split("?")[0]
            if key in CACHE:
                body, hdrs = CACHE[key]
                self._send(200, body, {**hdrs, "Age": "12"})
                return
            body = (
                f'<html><script src="//{host}/x.js"></script></html>'
                if host
                else "<html>clean</html>"
            )
            CACHE[key] = (body, {"Cache-Control": "public, max-age=3600"})
            self._send(200, body, {"Cache-Control": "public, max-age=3600"})
            return
        if parsed.path == "/safe":
            self._send(200, "<html>clean</html>", {"Cache-Control": "no-store"})
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
