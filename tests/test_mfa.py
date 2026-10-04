"""MfaChecker tests — bounded rate probes, step skip, OTP reuse on fakes."""

import http.server
import json
import threading

from blastradius.web.browser import BrowserSession
from blastradius.web.mfa import DEFAULT_PROBES, MAX_PROBES, MfaChecker


class Handler(http.server.BaseHTTPRequestHandler):
    REUSE_OTP = "123456"

    def log_message(self, *args):
        pass

    @property
    def _state(self):
        return self.server.__dict__.setdefault("mfa_state", {"failures": 0})

    def _send(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _fields(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def do_POST(self):
        fields = self._fields()
        if self.path == "/verify":
            self._send({"ok": False})
        elif self.path == "/verify-strict":
            state = self._state
            state["failures"] += 1
            if state["failures"] > 3:
                self._send({"error": "too many attempts, try again later"}, status=429)
            else:
                self._send({"ok": False})
        elif self.path == "/verify-reuse":
            # Failure-counting throttle that resets on success (the Vault
            # pattern): wrong OTPs still trip it, the valid OTP never does.
            state = self._state
            if fields.get("otp") == type(self).REUSE_OTP:
                state["failures"] = 0
                self._send({"ok": True})
            else:
                state["failures"] += 1
                if state["failures"] > 3:
                    self._send({"error": "too many attempts, try again later"}, status=429)
                else:
                    self._send({"ok": False})
        elif self.path == "/verify-broken":
            self._send({"ok": True})  # accepts anything, even wrong OTPs
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        cookies = self.headers.get("Cookie") or ""
        if self.path == "/dashboard" and ("pre=1" in cookies or "full=1" in cookies):
            raw = b"<html>DASHBOARD-SECRET</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.send_response(401)
            self.end_headers()


def _serve():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _base(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


def _pre_session():
    return BrowserSession(default_headers={"Cookie": "pre=1"})


VERIFY_MARKERS = ['"ok": true']
DASH_MARKERS = ["DASHBOARD-SECRET"]


# ------------------------------------------------------------- rate limit


def test_no_throttle_flagged():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {"verify_url": _base(server) + "/verify", "success_markers": VERIFY_MARKERS}
        )
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["mfa-no-rate-limit"]
    assert findings[0].cwe == "CWE-307"


def test_throttled_twin_silent():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {
                "verify_url": _base(server) + "/verify-strict",
                "success_markers": VERIFY_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


def test_wrong_otp_accepted_is_broken_verification():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {
                "verify_url": _base(server) + "/verify-broken",
                "success_markers": VERIFY_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["mfa-broken-verification"]
    assert findings[0].severity == "HIGH"


def test_probe_budget_bounded():
    assert MfaChecker().max_probes == DEFAULT_PROBES
    assert MfaChecker(max_probes=1000).max_probes == MAX_PROBES


# ------------------------------------------------------------- step skip


def test_step_skip_with_pre_session():
    server = _serve()
    try:
        checker = MfaChecker(session=_pre_session())
        findings = checker.check(
            {
                "dashboard_url": _base(server) + "/dashboard",
                "dashboard_markers": DASH_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["mfa-step-skip"]


def test_step_skip_sessionless_silent():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {
                "dashboard_url": _base(server) + "/dashboard",
                "dashboard_markers": DASH_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


# ------------------------------------------------------------- reuse


def test_otp_reuse_accepted_twice():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {
                "verify_url": _base(server) + "/verify-reuse",
                "reuse_otp": "123456",
                "success_markers": VERIFY_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["mfa-otp-reuse"]
    assert findings[0].cwe == "CWE-613"


def test_reuse_invalid_otp_no_finding():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {
                "verify_url": _base(server) + "/verify-reuse",
                "reuse_otp": "000000",
                "success_markers": VERIFY_MARKERS,
            }
        )
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


# ------------------------------------------------------------- discipline


def test_empty_config_refuses():
    assert MfaChecker().check({}) == []
    assert MfaChecker().check({"verify_url": "http://x/verify"}) == []


def test_dead_target_no_findings():
    checker = MfaChecker()
    assert (
        checker.check(
            {"verify_url": "http://127.0.0.1:1/verify", "success_markers": VERIFY_MARKERS}
        )
        == []
    )


def test_findings_carry_reporting_metadata():
    server = _serve()
    try:
        findings = MfaChecker().check(
            {"verify_url": _base(server) + "/verify", "success_markers": VERIFY_MARKERS}
        )
    finally:
        server.shutdown()
        server.server_close()
    assert findings
    for finding in findings:
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1
