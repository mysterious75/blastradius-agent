"""Fake transfer endpoints for the live-csrf benchmark target.

The "victim" is Cookie ``victim=1`` (the ambient authority a forged
request would ride). Success is the JSON marker {"transferred": true}.

* POST /transfer       — accepts any/no token  -> csrf-missing-token
* POST /transfer-weak  — accepts any token incl. garbage, but REQUIRES the
                         field present       -> csrf-weak-validation
* GET  /transfer-get   — state change over GET -> csrf-get-override
* POST /transfer-safe  — requires the exact token -> silent (FP guard)

All endpoints ignore requests without the victim cookie (no ambient
authority, no oracle).
"""

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler

_VALID_TOKEN = "valid-token-123"
_MARKER = {"transferred": True}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _authed(self) -> bool:
        return "victim=1" in (self.headers.get("Cookie") or "")

    def _send(self, payload: dict):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _fields(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return dict(urllib.parse.parse_qsl(body))

    def do_POST(self):
        fields = self._fields()
        if not self._authed():
            self._send({"transferred": False})
            return
        if self.path == "/transfer":
            self._send(_MARKER)  # token never inspected
        elif self.path == "/transfer-weak":
            if "csrf_token" in fields:
                self._send(_MARKER)  # presence checked, value not validated
            else:
                self._send({"transferred": False})
        elif self.path == "/transfer-safe":
            if fields.get("csrf_token") == _VALID_TOKEN:
                self._send(_MARKER)
            else:
                self._send({"transferred": False})
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/transfer-get") and self._authed():
            self._send(_MARKER)  # state change over GET
        else:
            self.send_response(404)
            self.end_headers()
