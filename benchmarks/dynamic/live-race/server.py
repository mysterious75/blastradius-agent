"""Fake coupon endpoints for the live-race benchmark target.

* POST /redeem      — racy check-then-act with a 0.3s window: every request
                       in a gated burst sees "unused", all succeed
                       -> race-condition
* POST /redeem-safe — the same endpoint behind a lock (atomic): exactly one
                       success per burst -> silent (FP guard)

Both credit nothing real; success is the JSON marker {"redeemed": true}.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler

_RACY_DELAY = 0.3


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    @property
    def _state(self):
        # Server-scoped (not class-scoped): every freshly booted server
        # starts unused, so repeated benchmark runs stay deterministic.
        return self.server.__dict__.setdefault(
            "race_state",
            {"used": False, "safe_used": False, "lock": threading.Lock()},
        )

    def _send(self, payload: dict):
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
            time.sleep(_RACY_DELAY)  # race window: check... act
            state["used"] = True
            self._send({"redeemed": True})
        elif self.path == "/redeem-safe":
            with state["lock"]:
                if state["safe_used"]:
                    ok = False
                else:
                    time.sleep(_RACY_DELAY)
                    state["safe_used"] = True
                    ok = True
            self._send({"redeemed": ok})
        else:
            self.send_response(404)
            self.end_headers()
