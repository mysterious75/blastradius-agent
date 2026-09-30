"""Dynamic benchmark target: live-sqli.

  /search?q=    error-based SQLi when q contains a quote (simulated)
  /items?id=    boolean-differential SQLi (different bodies for 1=1 vs 1=2)
  /safe?q=      parameterized control (identical bodies, no error)

Ground truth: sqli-error on /search, sqli-boolean on /items, nothing on /safe.
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/search":
            q = qs.get("q", [""])[0]
            if "'" in q or '"' in q:
                return self._send(
                    200, '{"error":"You have an error in your SQL syntax near \'%s\'"}' % q[:20]
                )
            return self._send(200, b'{"results":[]}')
        if parsed.path == "/items":
            ident = qs.get("id", [""])[0]
            if "1=1" in ident:
                return self._send(200, b'{"items":["a","b","c","d"]}')
            return self._send(200, b'{"items":[]}')
        if parsed.path == "/safe":
            return self._send(200, b'{"results":[]}')
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
