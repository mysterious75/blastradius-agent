"""Tests for the BlastRadius Prometheus tool wrappers.

These run WITHOUT cai-framework installed: the wrappers fall back to plain
functions, so the scanner wiring itself is fully exercised here.
"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blastradius.tools import (
    prometheus_adversarial_validate,
    prometheus_sqli_scan,
    prometheus_ssrf_scan,
    prometheus_xss_scan,
)


class _FakeVulnApp(BaseHTTPRequestHandler):
    """Local app that emits a MySQL syntax error for any value containing a quote."""

    def _respond(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if self.command == "POST":
            query.update(urllib.parse.parse_qs(body.decode("utf-8", "replace")))
        values = [v for vals in query.values() for v in vals]
        if any("'" in v for v in values):
            payload = b"DB ERROR: You have an error in your SQL syntax near '' at line 1"
        else:
            payload = b"<html><body>Welcome. Page loaded fine.</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def target_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeVulnApp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/page?id=1"
    yield url
    server.shutdown()
    server.server_close()


def test_all_tools_are_callable():
    for tool in (
        prometheus_sqli_scan,
        prometheus_xss_scan,
        prometheus_ssrf_scan,
        prometheus_adversarial_validate,
    ):
        assert callable(tool)


def test_sqli_scan_finds_error_based_injection(target_url):
    result = prometheus_sqli_scan(target_url, rps=50.0, timeout=5.0)
    findings = json.loads(result)
    assert isinstance(findings, list)
    assert findings, "expected at least one SQLi finding against the fake app"
    sqli = [f for f in findings if f["vuln_type"] == "SQL Injection" and f["verified"]]
    assert sqli, f"expected a verified SQL Injection finding, got {findings}"
    assert sqli[0]["parameter"] == "id"


def test_scan_unreachable_target_returns_empty_list():
    result = prometheus_sqli_scan("http://127.0.0.1:1/x?id=1", rps=50.0, timeout=2.0)
    assert json.loads(result) == []


def test_invalid_params_json_is_rejected(target_url):
    with pytest.raises(ValueError, match="not valid JSON"):
        prometheus_sqli_scan(target_url, params_json="not-json", rps=50.0)


def test_adversarial_validate_returns_verdict():
    finding = {
        "vuln_type": "SQL Injection",
        "title": "Error-based SQLi in parameter 'id'",
        "severity": "CRITICAL",
        "url": "http://localhost/page?id=1",
        "parameter": "id",
        "method": "GET",
        "payload": "' OR 1=1--",
        "evidence": "SQL error from MySQL detected in response for parameter 'id'.",
        "remediation": "Use parameterized queries",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "verified": True,
        "confidence": "HIGH",
    }
    result = prometheus_adversarial_validate(json.dumps(finding))
    results = json.loads(result)
    assert len(results) == 1
    assert results[0]["verdict"] in {
        "confirmed",
        "likely_false_positive",
        "false_positive",
        "needs_manual_review",
    }
    assert results[0]["vuln_type"] == finding["vuln_type"]


def test_adversarial_validate_batch_and_bad_input():
    empty = prometheus_adversarial_validate("[]")
    assert json.loads(empty) == []
    with pytest.raises(ValueError, match="not valid JSON"):
        prometheus_adversarial_validate("not-json")
    with pytest.raises(ValueError, match="JSON object or a list"):
        prometheus_adversarial_validate('"just a string"')
