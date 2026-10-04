"""CsrfChecker tests — passive form analysis + token harness on fakes."""

import http.server
import json
import threading
import urllib.parse

from blastradius.web.browser import BrowserSession
from blastradius.web.csrf import (
    CsrfChecker,
    form_has_token,
    post_forms,
)


class Handler(http.server.BaseHTTPRequestHandler):
    VALID = "valid-token-123"

    def log_message(self, *args):
        pass

    def _authed(self):
        return "victim=1" in (self.headers.get("Cookie") or "")

    def _send(self, payload):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        fields = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8", "replace")))
        if not self._authed():
            self._send({"transferred": False})
            return
        if self.path == "/transfer":
            self._send({"transferred": True})
        elif self.path == "/transfer-weak":
            self._send({"transferred": "csrf_token" in fields})
        elif self.path == "/transfer-safe":
            self._send({"transferred": fields.get("csrf_token") == type(self).VALID})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/transfer-get") and self._authed():
            self._send({"transferred": True})
        else:
            self.send_response(404)
            self.end_headers()


def _serve():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _base(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


def _victim_checker():
    session = BrowserSession(default_headers={"Cookie": "victim=1"})
    return CsrfChecker(session=session)


MARKERS = ['"transferred": true']


# ------------------------------------------------------------- passive tier


def test_form_without_token_flagged():
    html = '<form method="POST" action="/transfer"><input name="to"></form>'
    findings = CsrfChecker().check_forms("http://lab.invalid/", html)
    assert len(findings) == 1
    assert findings[0].check == "csrf-token-missing"


def test_form_with_token_clean():
    html = (
        '<form method="POST" action="/transfer">'
        '<input type="hidden" name="authenticity_token" value="abc">'
        '<input name="to"></form>'
    )
    assert CsrfChecker().check_forms("http://lab.invalid/", html) == []


def test_get_forms_ignored():
    html = '<form method="GET" action="/search"><input name="q"></form>'
    assert CsrfChecker().check_forms("http://lab.invalid/", html) == []


def test_form_has_token_variants():
    assert form_has_token('<input name="csrfmiddlewaretoken">')
    assert form_has_token('<input name="__RequestVerificationToken">')
    assert not form_has_token('<input name="email">')
    assert post_forms("no forms here") == []


# ------------------------------------------------------------- active tier


def test_missing_token_accepted():
    server = _serve()
    try:
        findings = _victim_checker().check([_base(server) + "/transfer"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["csrf-missing-token"]
    assert findings[0].severity == "HIGH"


def test_garbage_token_accepted():
    server = _serve()
    try:
        findings = _victim_checker().check([_base(server) + "/transfer-weak"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["csrf-weak-validation"]


def test_get_override_accepted():
    server = _serve()
    try:
        findings = _victim_checker().check([_base(server) + "/transfer-get"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["csrf-get-override"]


def test_safe_endpoint_silent():
    server = _serve()
    try:
        findings = _victim_checker().check([_base(server) + "/transfer-safe"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


def test_sessionless_never_counts():
    """Without ambient authority a 200 proves nothing — harness needs a session."""
    server = _serve()
    try:
        # No victim cookie: every endpoint answers transferred:false.
        findings = CsrfChecker().check([_base(server) + "/transfer"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


def test_no_oracle_no_findings():
    server = _serve()
    try:
        assert _victim_checker().check([_base(server) + "/transfer"], []) == []
        assert _victim_checker().check([], MARKERS) == []
    finally:
        server.shutdown()
        server.server_close()


def test_findings_carry_reporting_metadata():
    server = _serve()
    try:
        findings = _victim_checker().check([_base(server) + "/transfer"], MARKERS)
    finally:
        server.shutdown()
        server.server_close()
    assert findings
    for finding in findings:
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1
