"""Fake desync backends for the live-smuggle benchmark target.

Three personalities on separate 127.0.0.1 ports (one finding each at most —
the checker honors Kettle ordering and stops after the first positive, so
no single backend may exhibit both desyncs):

* CL.TE personality  -> smuggle-cl-te (invalid chunk never resolves)
* TE.CL personality  -> smuggle-te-cl (stray X corrupts the follow-up)
* HARDENED           -> zero findings (everything 200s fast)

No real desync engine is implemented — only the two client-visible
observables (timeout vs fast answer; follow-up corruption vs clean) that
the checker keys on. That is exactly the contract a detector must satisfy.
"""

import socketserver
import threading
import time

VULN_DELAY = 5.0


class _QuietTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def _read_request(request):
    """Read headers + declared body bytes (fake-CL framing)."""
    request.settimeout(10)
    data = b""
    try:
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = request.recv(1024)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    head, _, rest = data.partition(b"\r\n\r\n")
    try:
        length = 0
        for line in head.decode("iso-8859-1").split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
    except ValueError:
        length = 0
    body = rest
    try:
        while len(body) < length:
            chunk = request.recv(1024)
            if not chunk:
                break
            body += chunk
    except Exception:
        pass
    return head.decode("iso-8859-1", errors="replace"), body


def _respond(request, status, body=b"x", close=True):
    raw = (
        f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
        f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n"
    ).encode() + body
    try:
        request.sendall(raw)
    except Exception:
        pass


class VulnClteHandler(socketserver.BaseRequestHandler):
    """TE-backend personality: the invalid chunk never resolves (timeout)."""

    def handle(self):
        head, body = _read_request(self.request)
        is_probe = "Transfer-Encoding:" in head and "chunked" in head.lower()
        if is_probe and body.startswith(b"1\r\nZ"):
            time.sleep(VULN_DELAY)
            return
        _respond(self.request, "200 OK")


class VulnTeclHandler(socketserver.BaseRequestHandler):
    """Desynced-pair personality: POST 200s, stray X corrupts the follow-up."""

    def handle(self):
        head, body = _read_request(self.request)
        is_probe = "Transfer-Encoding:" in head and "chunked" in head.lower()
        if is_probe and body.startswith(b"0\r\n\r\nX"):
            _respond(self.request, "200 OK", close=False)
            follow_head, _ = _read_request(self.request)
            if follow_head:
                _respond(self.request, "404 Not Found")
            return
        _respond(self.request, "200 OK")


class HardenedHandler(socketserver.BaseRequestHandler):
    """Normalizes everything: every request (and follow-up) 200s fast."""

    def handle(self):
        head, body = _read_request(self.request)
        _respond(self.request, "200 OK", close=False)
        # Keep serving follow-ups on the same connection like a keep-alive server.
        for _ in range(3):
            follow_head, _ = _read_request(self.request)
            if not follow_head:
                break
            _respond(self.request, "200 OK", close=False)


def make_servers():
    """Boot (clte, tecl, hardened); return [(role, server)]. Caller shuts down."""
    servers = []
    for role, handler in (
        ("clte", VulnClteHandler),
        ("tecl", VulnTeclHandler),
        ("hardened", HardenedHandler),
    ):
        server = _QuietTCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        servers.append((role, server))
    return servers
