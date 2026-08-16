"""JS endpoint extraction tests — endpoints inside script files get crawled.

Offline against a local stdlib HTTP server: the index page references
/app.js, which contains fetch/axios/WebSocket/string-literal API references.
The scanner must discover and crawl /search from the JS and find the
reflected XSS there.
"""

import http.server
import threading
import urllib.parse

import pytest

from blastradius.web.scanner import DynamicWebScanner


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/":
            self._send(
                200,
                b"<html><body>"
                b'<script src="/app.js"></script>'
                b'<script src="https://cdn.invalid/lib.js"></script>'  # cross-origin: ignored
                b"</body></html>",
            )
        elif path == "/app.js":
            self._send(
                200,
                b"""fetch('/search?q=1');
axios.post('/api/user', {name: 'x'});
new WebSocket('ws://127.0.0.1:9999/socket');
const a = '/v1/items';
""",
                headers={"Content-Type": "application/javascript"},
            )
        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>you searched: {q}</body></html>".encode())
        elif path.startswith("/api/user"):
            self._send(200, b'{"ok":1}')
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode(errors="replace")
        self._send(200, f"<html><body>echo: {body}</body></html>".encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server_url():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_scanner_discovers_js_endpoints_and_crawls_them(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    xss = [f for f in findings if f.check == "xss"]
    assert xss, [f.check for f in findings]
    # The /search endpoint was only referenced inside app.js — the scanner
    # must have discovered it from the JS and crawled it.
    assert any("search" in f.url for f in xss)


def test_js_endpoints_are_collected(server_url):
    scanner = DynamicWebScanner(probe_exposed=False)
    page = scanner.browser.get(server_url + "/")
    endpoints = scanner._collect_js_endpoints(server_url + "/", page.text)
    assert any("search" in e for e in endpoints)
    assert any("api/user" in e for e in endpoints)
    # Cross-origin script (cdn.invalid) must never be fetched or returned.
    assert all("cdn.invalid" not in e for e in endpoints)
