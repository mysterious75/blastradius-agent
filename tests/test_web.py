"""Dynamic web testing tests — offline against a local stdlib HTTP server.

Exercises the HTTPProxy, BrowserSession and DynamicWebScanner with a real
local server: no mocks, no network egress.
"""

import http.server
import threading
import urllib.parse

import pytest

from blastradius.web.browser import BrowserSession
from blastradius.web.proxy import HTTPProxy
from blastradius.web.scanner import DynamicWebScanner


class _Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status, body, headers=None, location=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if location:
            self.send_header("Location", location)
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
                b'<a href="/search?q=1">s</a>'
                b'<a href="/safe?q=1">x</a>'
                b'<a href="/redirect?next=/">r</a>'
                b'<a href="/cors">c</a>'
                b'<a href="/list">l</a>'
                b'<form method="post" action="/submit"><input name="msg"></form>'
                b"</body></html>",
            )
        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>you searched: {q}</body></html>".encode())
        elif path == "/safe":
            # Fully entity-encode the echo so no probe text can appear verbatim.
            q = qs.get("q", [""])[0]
            safe = "".join(f"&#{ord(ch)};" for ch in q)
            self._send(200, f"<html><body>you searched: {safe}</body></html>".encode())
        elif path == "/redirect":
            self._send(302, b"", location=qs.get("next", [""])[0] or "/")
        elif path == "/cors":
            self._send(
                200,
                b'{"ok":1}',
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        elif path in ("/.git/config", "/.env", "/admin"):
            self._send(200, b"[core]\n\tbare = false\n")
        elif path == "/list":
            self._send(200, b"<h1>Index of /</h1>")
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


def _checks(findings):
    return {f.check for f in findings}


def test_proxy_records_and_sitemap(server_url):
    proxy = HTTPProxy().start()
    try:
        browser = BrowserSession(proxy=f"http://127.0.0.1:{proxy.port}")
        page = browser.get(server_url + "/search", params={"q": "hi"})
        assert page.status == 200
        assert page.text == "<html><body>you searched: hi</body></html>"
        assert server_url + "/search?q=hi" in proxy.sitemap()
        record = proxy.traffic[0]
        assert record.method == "GET"
        assert record.status == 200
    finally:
        proxy.stop()


def test_browser_cookie_jar(server_url):
    browser = BrowserSession()
    page = browser.get(server_url + "/")
    assert page.status == 200
    assert len(page.cookies) == 0  # server sets none; jar API works


def test_browser_post_form(server_url):
    browser = BrowserSession()
    page = browser.post(server_url + "/submit", {"msg": "hello"})
    assert page.status == 200
    assert "hello" in page.text


def test_scanner_finds_reflected_xss(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    xss = [f for f in findings if f.check == "xss"]
    assert xss, [f.check for f in findings]
    assert any("search" in f.url for f in xss)


def test_scanner_safe_endpoint_not_flagged(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    xss_urls = {f.url for f in findings if f.check == "xss"}
    assert not any("safe" in u for u in xss_urls)


def test_scanner_finds_open_redirect(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    redirects = [f for f in findings if f.check == "redirect"]
    assert redirects
    assert all("redirect" in f.url or "?next=" in f.url for f in redirects)


def test_scanner_finds_missing_security_headers(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    assert any(f.check == "headers" for f in findings)


def test_scanner_finds_cors_wildcard(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    assert any(f.check == "cors" for f in findings)


def test_scanner_finds_directory_listing(server_url):
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    assert any(f.check == "listing" for f in findings)


def test_scanner_exposed_probe(server_url):
    findings = DynamicWebScanner(probe_exposed=True).scan(server_url)
    exposed = [f for f in findings if f.check == "exposure"]
    assert any("/.git" in f.url or "/.env" in f.url or "/admin" in f.url for f in exposed)
