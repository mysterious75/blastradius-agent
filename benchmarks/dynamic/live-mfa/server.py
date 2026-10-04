"""Fake MFA endpoints for the live-mfa benchmark target.

Sessions: Cookie ``pre=1`` is the pre-MFA session (password done, OTP
pending); Cookie ``full=1`` is post-MFA. Success markers:
- verify/reuse success: {"ok": true}
- dashboard content: "DASHBOARD-SECRET"

* POST /verify        — wrong OTPs always 200 {"ok": false}, never throttles
                        -> mfa-no-rate-limit
* POST /verify-strict — 429 after 3 attempts -> silent (throttle guard)
* GET  /dashboard     — serves post-login content to pre=1 (MFA never
                        completed) -> mfa-step-skip
* POST /verify-reuse  — OTP "123456" accepted every time, never invalidated
                        -> mfa-otp-reuse
"""

import json
from http.server import BaseHTTPRequestHandler

_REUSE_OTP = "123456"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    @property
    def _state(self):
        return self.server.__dict__.setdefault("mfa_state", {"failures": 0})

    def _cookies(self):
        return self.headers.get("Cookie") or ""

    def _send(self, payload, status=200):
        if isinstance(payload, dict):
            raw = json.dumps(payload).encode()
            ctype = "application/json"
        else:
            raw = payload.encode()
            ctype = "text/html"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
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
            self._send({"ok": False})  # wrong OTP, never throttled
        elif self.path == "/verify-strict":
            state = self._state
            state["failures"] += 1
            if state["failures"] > 3:
                self._send({"error": "too many attempts, try again later"}, status=429)
            else:
                self._send({"ok": False})
        elif self.path == "/verify-reuse":
            # Failure-counting throttle that resets on success: wrong OTPs
            # still trip it, the valid OTP never does — so the rate probe
            # stays silent here while the reuse probe fires.
            state = self._state
            if fields.get("otp") == _REUSE_OTP:
                state["failures"] = 0
                self._send({"ok": True})
            else:
                state["failures"] += 1
                if state["failures"] > 3:
                    self._send({"error": "too many attempts, try again later"}, status=429)
                else:
                    self._send({"ok": False})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        cookies = self._cookies()
        if self.path == "/dashboard" and ("pre=1" in cookies or "full=1" in cookies):
            self._send("<html>DASHBOARD-SECRET</html>")
        else:
            self.send_response(401)
            self.end_headers()
