"""Payload corpus integration tests — real payload loading and web-scanner wiring.

Verifies that blastradius.payloads serves real HackerOne corpus payloads with
a graceful fallback to the built-in defaults, and that DynamicWebScanner still
detects reflected XSS when driven by the combined payload list. Offline: the
web test runs against a local stdlib HTTP server (no mocks, no egress).
"""

import http.server
import threading
import urllib.parse
from pathlib import Path

import pytest

import blastradius.payloads as payloads_mod
from blastradius.web.scanner import DynamicWebScanner

REAL_CORPUS_PRESENT = payloads_mod._corpus_path.is_file()


class _ReflectHandler(http.server.BaseHTTPRequestHandler):
    """Tiny server that reflects the `q` query param and `msg` form field."""

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, qs = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/":
            self._send(
                200,
                b'<html><body><a href="/search?q=1">s</a></body></html>',
            )
        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body>you searched: {q}</body></html>".encode())
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
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ReflectHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_xss_payloads_fallback_when_corpus_missing(monkeypatch):
    """Corpus path pointing at nothing -> built-in defaults are returned."""
    monkeypatch.setattr(
        payloads_mod,
        "_corpus_path",
        Path("does-not-exist/payload_corpus.json"),
    )
    got = payloads_mod.xss_payloads()
    assert "<script>alert(1)</script>" in got
    assert '"><img src=x onerror=alert(1)>' in got


@pytest.mark.skipif(
    not REAL_CORPUS_PRESENT,
    reason="payload_corpus.json not present (gitignored data file)",
)
def test_xss_payloads_load_real_payloads():
    """Real corpus present -> list is non-empty and carries corpus payloads."""
    payloads = payloads_mod.xss_payloads()
    assert payloads
    defaults = set(payloads_mod.DEFAULT_XSS_PAYLOADS)
    assert any(payload not in defaults for payload in payloads)
    assert all(3 <= len(payload) <= 80 for payload in payloads)


def test_web_scanner_still_detects_xss(server_url):
    """Scanner using the combined payload list still flags reflected XSS."""
    findings = DynamicWebScanner(probe_exposed=False).scan(server_url)
    xss = [f for f in findings if f.check == "xss"]
    assert xss, [f.check for f in findings]
    assert any("search" in f.url for f in xss)
