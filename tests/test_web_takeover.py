"""Header-policy, CORS-reflection and subdomain-takeover scanner tests.

Offline: every scenario runs against a local stdlib HTTP server (no mocks,
no network egress).
"""

import http.server
import threading

import pytest

from blastradius.web.browser import BrowserSession
from blastradius.web.scanner import DynamicWebScanner
from blastradius.web.takeover import check_takeover


class _PlainHandler(http.server.BaseHTTPRequestHandler):
    """Serves a plain page with no security headers."""

    def do_GET(self):
        body = b"<html><body>plain</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _SecureHandler(_PlainHandler):
    """Sends OWASP-compliant HSTS/XFO/nosniff headers."""

    def do_GET(self):
        body = b"<html><body>secure</body></html>"
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CorsReflectHandler(_PlainHandler):
    """Echoes the request Origin in Access-Control-Allow-Origin."""

    def do_GET(self):
        body = b'{"ok":1}'
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _S3Handler(_PlainHandler):
    """Serves the AWS S3 'bucket does not exist' error page."""

    def do_GET(self):
        body = b"The specified bucket does not exist"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server_factory():
    servers = []

    def _make(handler_cls):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        servers.append(httpd)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    yield _make
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def _headers_findings(findings):
    return [f for f in findings if f.check == "headers"]


# ----------------------------------------------------------------------
# Header-policy checks
# ----------------------------------------------------------------------


def test_header_policy_flags_missing_headers(server_factory):
    url = server_factory(_PlainHandler)
    findings = DynamicWebScanner(probe_exposed=False).scan(url)
    headers = _headers_findings(findings)
    assert headers
    assert any("Strict-Transport-Security" in f.evidence for f in headers)
    assert any("X-Content-Type-Options" in f.evidence for f in headers)
    assert any("OWASP expected" in f.evidence for f in headers)


def test_header_policy_no_finding_when_hsts_compliant(server_factory):
    url = server_factory(_SecureHandler)
    findings = DynamicWebScanner(probe_exposed=False).scan(url)
    headers = _headers_findings(findings)
    # Correct HSTS (includeSubDomains), nosniff and XFO must not be flagged.
    assert not any("Strict-Transport-Security" in f.evidence for f in headers)
    assert not any("X-Content-Type-Options" in f.evidence for f in headers)
    assert not any("X-Frame-Options" in f.evidence for f in headers)


# ----------------------------------------------------------------------
# CORS reflection
# ----------------------------------------------------------------------


def test_cors_reflection_flagged(server_factory):
    url = server_factory(_CorsReflectHandler)
    findings = DynamicWebScanner(probe_exposed=False).scan(url)
    cors = [f for f in findings if f.check == "cors"]
    assert cors
    assert any("reflected Origin" in f.evidence for f in cors)


# ----------------------------------------------------------------------
# Subdomain takeover
# ----------------------------------------------------------------------


def test_check_takeover_finds_s3(server_factory):
    url = server_factory(_S3Handler)
    matches = check_takeover(url, BrowserSession())
    assert any(m["service"] == "AWS S3" for m in matches)
    assert any("specified bucket does not exist" in m["evidence"] for m in matches)


def test_check_takeover_no_match_on_plain_page(server_factory):
    url = server_factory(_PlainHandler)
    assert check_takeover(url, BrowserSession()) == []


def test_scanner_reports_takeover_candidate(server_factory):
    url = server_factory(_S3Handler)
    findings = DynamicWebScanner(probe_exposed=False).scan(url)
    takeover = [f for f in findings if f.check == "takeover"]
    assert takeover
    assert any("AWS S3" in f.evidence for f in takeover)
    assert all(f.cwe == "CWE-706" for f in takeover)
    assert all(f.severity == "MEDIUM" for f in takeover)


def test_scanner_takeover_opt_out(server_factory):
    url = server_factory(_S3Handler)
    findings = DynamicWebScanner(probe_exposed=False, check_takeover=False).scan(url)
    assert not any(f.check == "takeover" for f in findings)
