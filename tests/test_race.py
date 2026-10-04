"""RaceChecker tests — gated bursts against racy/atomic fake endpoints."""

import http.server
import json
import threading
import time

from blastradius.web.race import MAX_BURST, RaceChecker


class Handler(http.server.BaseHTTPRequestHandler):
    delay = 0.2

    def log_message(self, *args):
        pass

    @property
    def _state(self):
        return self.server.__dict__.setdefault(
            "race_state",
            {"used": False, "safe_used": False, "lock": threading.Lock()},
        )

    def _send(self, payload):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        state = self._state
        if self.path == "/redeem":
            if state["used"]:
                self._send({"redeemed": False})
                return
            time.sleep(type(self).delay)
            state["used"] = True
            self._send({"redeemed": True})
        elif self.path == "/redeem-safe":
            with state["lock"]:
                if state["safe_used"]:
                    ok = False
                else:
                    time.sleep(type(self).delay)
                    state["safe_used"] = True
                    ok = True
            self._send({"redeemed": ok})
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


# ------------------------------------------------------------- behavior


def test_racy_endpoint_double_success():
    server = _serve()
    try:
        checker = RaceChecker(burst=8)
        findings = checker.check([_base(server) + "/redeem"], ['"redeemed": true'])
    finally:
        server.shutdown()
        server.server_close()
    assert len(findings) == 1
    hit = findings[0]
    assert hit.check == "race-condition"
    assert hit.severity == "HIGH"
    assert hit.cwe == "CWE-367"
    assert "8 parallel" in hit.evidence


def test_atomic_endpoint_silent():
    server = _serve()
    try:
        checker = RaceChecker(burst=8)
        findings = checker.check([_base(server) + "/redeem-safe"], ['"redeemed": true'])
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


def test_no_markers_no_oracle_no_findings():
    server = _serve()
    try:
        checker = RaceChecker(burst=8)
        assert checker.check([_base(server) + "/redeem"], []) == []
    finally:
        server.shutdown()
        server.server_close()


def test_wrong_marker_no_findings():
    server = _serve()
    try:
        checker = RaceChecker(burst=8)
        assert checker.check([_base(server) + "/redeem"], ["no-such-marker"]) == []
    finally:
        server.shutdown()
        server.server_close()


def test_dead_target_no_findings():
    checker = RaceChecker(burst=4)
    assert checker.check(["http://127.0.0.1:1/redeem"], ['"redeemed": true']) == []


def test_burst_is_capped():
    assert RaceChecker(burst=1000).burst == MAX_BURST
    assert RaceChecker(burst=1).burst == 2


def test_findings_carry_reporting_metadata():
    server = _serve()
    try:
        checker = RaceChecker(burst=6)
        findings = checker.check([_base(server) + "/redeem"], ['"redeemed": true'])
    finally:
        server.shutdown()
        server.server_close()
    assert findings
    for finding in findings:
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1
