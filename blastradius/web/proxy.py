"""Minimal HTTP(S) interception proxy — stdlib only.

Records every request/response it forwards so callers can inspect traffic,
replay requests, and build sitemaps (the "Caido-lite" tooling layer). Plain
HTTP is fully intercepted; HTTPS is tunneled via CONNECT (TLS content is
opaque by design — use the BrowserSession against http targets for
interception).

Example:
    proxy = HTTPProxy()
    proxy.start()
    page = BrowserSession(proxy=f"http://{proxy.host}:{proxy.port}").get("http://target/")
    print(proxy.sitemap())
    proxy.stop()
"""

import http.client
import http.server
import select
import socket
import socketserver
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TrafficRecord:
    """One intercepted request/response pair."""

    method: str
    url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""


def _forward(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> tuple:
    """Forward a request to its origin over plain HTTP and return the response."""
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    status, resp_headers = resp.status, dict(resp.getheaders())
    conn.close()
    return status, resp_headers, data


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_HEAD(self):
        self._handle("HEAD")

    def do_OPTIONS(self):
        self._handle("OPTIONS")

    def _handle(self, method: str) -> None:
        url = self.path  # absolute-form URL in proxy requests
        body = None
        if method in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
        forward_headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length", "connection")
        }
        try:
            status, resp_headers, data = _forward(method, url, forward_headers, body)
        except Exception as exc:
            status, resp_headers, data = 502, {}, str(exc).encode()
        self.server.proxy.record(
            method,
            url,
            dict(self.headers),
            (body or b"").decode(errors="replace"),
            status,
            resp_headers,
            data.decode(errors="replace"),
        )
        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() not in ("connection", "transfer-encoding"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_CONNECT(self) -> None:
        """Tunnel HTTPS traffic (recorded as a CONNECT marker only)."""
        host, _, port = self.path.partition(":")
        try:
            self.send_response(200, "Connection established")
            self.end_headers()
            upstream = socket.create_connection((host, int(port)), timeout=10)
            self.server.proxy.record("CONNECT", self.path, dict(self.headers))
            self.connection.setblocking(False)
            upstream.setblocking(False)
            while True:
                readable, _, _ = select.select([self.connection, upstream], [], [], 1)
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        raise ConnectionError
                    (upstream if sock is self.connection else self.connection).sendall(data)
        except Exception:
            pass
        finally:
            self.close_connection = True

    def log_message(self, *args) -> None:
        pass  # silence default stderr logging


class HTTPProxy:
    """Interception proxy that records forwarded traffic."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.traffic: List[TrafficRecord] = []
        self._lock = threading.Lock()
        self._server = socketserver.ThreadingTCPServer((host, port), _ProxyHandler)
        self._server.daemon_threads = True
        self._server.proxy = self
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def record(
        self,
        method,
        url,
        request_headers,
        request_body="",
        status=0,
        response_headers=None,
        response_body="",
    ) -> None:
        with self._lock:
            self.traffic.append(
                TrafficRecord(
                    method=method,
                    url=url,
                    request_headers=request_headers,
                    request_body=request_body,
                    status=status,
                    response_headers=response_headers or {},
                    response_body=response_body,
                )
            )

    def start(self) -> "HTTPProxy":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def sitemap(self) -> List[str]:
        """Unique request URLs seen so far (plain-HTTP traffic only)."""
        seen = []
        with self._lock:
            for rec in self.traffic:
                if rec.method != "CONNECT" and rec.url not in seen:
                    seen.append(rec.url)
        return seen

    def replay(self, index: int) -> Optional[TrafficRecord]:
        """Return the recorded traffic entry at ``index`` (or None)."""
        with self._lock:
            if 0 <= index < len(self.traffic):
                return self.traffic[index]
        return None
