"""Dynamic benchmark target: live-ssrf.

  /fetch?url=<u>   fetches <u> server-side and returns the HTTP status (vuln)
  /static          returns fixed content, no fetch (safe control)

Ground truth (manifest.json): exactly one ``ssrf`` hit (on /fetch).
stdlib only; binds 127.0.0.1 on an ephemeral port chosen by the runner.
"""

import http.server
import urllib.parse
import urllib.request


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/fetch":
            target = urllib.parse.parse_qs(parsed.query).get("url", [""])[0]
            if not target:
                return self._send(400, b'{"error":"missing url"}')
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "bench-ssrf/1.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    code = r.status
                return self._send(200, f'{{"fetched":true,"status":{code}}}'.encode())
            except Exception as exc:
                return self._send(200, f'{{"fetched":false,"error":"{str(exc)[:60]}"}}'.encode())
        if parsed.path == "/static":
            return self._send(200, b'{"fixed":true}')
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass
