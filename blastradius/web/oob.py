"""Out-of-band (OOB) listener — a tiny local HTTP server that records callbacks.

Used by the live SSRF check to observe server-side fetches that a normal
response cannot reveal. Runs on localhost, records ``(path, remote_addr,
headers, time)`` per hit, and exposes ``hits_for(marker)``.

Where to point a target at this listener:
  * a publicly reachable location (this listener is only for local/demo tests —
    the callback URL in a real hunt must be reachable from the target, e.g. an
    interactsh/webhook.site URL); or
  * in tests, wire a fake listener with the same ``hits_for`` interface.

The HTTP transport is stdlib; ``start()``/``stop()`` are idempotent.
"""

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Tuple


@dataclass
class OobHit:
    path: str
    remote_addr: str
    headers: Dict[str, str] = field(default_factory=dict)
    at: float = 0.0


class _Handler(BaseHTTPRequestHandler):
    def _record(self):
        self.server.record(self.path, self.client_address[0], dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_HEAD = _record
    do_PUT = _record

    def log_message(self, *a):  # silence
        pass


class OobListener:
    """Local HTTP listener recording every inbound request."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._server: HTTPServer = None
        self._thread: threading.Thread = None
        self.hits: List[OobHit] = []
        self._lock = threading.Lock()

    # -- lifecycle -----------------------------------------------------
    def start(self) -> "OobListener":
        if self._server is not None:
            return self
        self._server = HTTPServer((self.host, self.port), _Handler)
        self._server.record = self._record  # type: ignore[attr-defined]
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    # -- recording -----------------------------------------------------
    def _record(self, path: str, remote_addr: str, headers: Dict[str, str]) -> None:
        with self._lock:
            self.hits.append(OobHit(path=path, remote_addr=remote_addr,
                                    headers=headers, at=time.time()))

    def hits_for(self, marker: str) -> List[OobHit]:
        with self._lock:
            return [h for h in self.hits if marker in h.path]

    @property
    def callback_base(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
