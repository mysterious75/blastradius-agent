"""SmuggleChecker tests — probe builders (pure) + fake desync backends."""

import socketserver
import threading
import time

from blastradius.web.smuggle import (
    SmuggleChecker,
    _DESYNC_STATUS,
    build_clte_probe,
    build_followup,
    build_tecl_probe,
)


class _QuietTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def _read_request(request):
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
    length = 0
    for line in head.decode("iso-8859-1").split("\r\n"):
        if line.lower().startswith("content-length:"):
            with __import__("contextlib").suppress(ValueError):
                length = int(line.split(":", 1)[1].strip())
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


def _respond(request, status, close=True):
    raw = (
        f"HTTP/1.1 {status}\r\nContent-Length: 1\r\n"
        f"Connection: {'close' if close else 'keep-alive'}\r\n\r\nx"
    ).encode()
    try:
        request.sendall(raw)
    except Exception:
        pass


class _VulnClteHandler(socketserver.BaseRequestHandler):
    def handle(self):
        head, body = _read_request(self.request)
        is_probe = "Transfer-Encoding:" in head and "chunked" in head.lower()
        if is_probe and body.startswith(b"1\r\nZ"):
            time.sleep(3.0)  # TE-backend waits for a valid chunk
            return
        _respond(self.request, "200 OK", close=False)
        for _ in range(3):
            follow_head, _ = _read_request(self.request)
            if not follow_head:
                break
            _respond(self.request, "200 OK", close=False)


class _VulnTeclHandler(socketserver.BaseRequestHandler):
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


class _HardenedHandler(socketserver.BaseRequestHandler):
    def handle(self):
        head, body = _read_request(self.request)
        _respond(self.request, "200 OK", close=False)
        for _ in range(3):
            follow_head, _ = _read_request(self.request)
            if not follow_head:
                break
            _respond(self.request, "200 OK", close=False)


def _serve(handler):
    server = _QuietTCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.daemon = True
    thread.start()
    return server


def _url(server):
    return f"http://127.0.0.1:{server.server_address[1]}/smuggle"


# ------------------------------------------------------------- builders


def test_clte_probe_shape():
    raw = build_clte_probe("lab.invalid", "/smuggle")
    assert b"Content-Length: 4" in raw
    assert b"Transfer-Encoding: chunked" in raw
    assert raw.endswith(b"1\r\nZ\r\nQ")


def test_tecl_probe_shape():
    raw = build_tecl_probe("lab.invalid", "/smuggle")
    assert b"Content-Length: 6" in raw
    assert b"Transfer-Encoding: chunked" in raw
    assert raw.endswith(b"0\r\n\r\nX")


def test_followup_targets_same_path():
    raw = build_followup("lab.invalid", "/smuggle")
    assert raw.startswith(b"GET /smuggle HTTP/1.1")


def test_desync_status_matches_error_status():
    assert _DESYNC_STATUS.search(b"HTTP/1.1 404 Not Found\r\n")
    assert _DESYNC_STATUS.search(b"HTTP/1.1 400 Bad Request\r\n")
    assert not _DESYNC_STATUS.search(b"HTTP/1.1 200 OK\r\n")


# ------------------------------------------------------------- live fakes


def test_vuln_clte_backend_reports_clte_only():
    """Kettle ordering: the checker stops at the first positive."""
    server = _serve(_VulnClteHandler)
    try:
        checker = SmuggleChecker(connect_timeout=2, read_timeout=2)
        findings = checker.check([_url(server)])
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["smuggle-cl-te"]
    assert findings[0].cwe == "CWE-444" and findings[0].severity == "HIGH"


def test_vuln_tecl_backend_reports_tecl_only():
    server = _serve(_VulnTeclHandler)
    try:
        checker = SmuggleChecker(connect_timeout=2, read_timeout=2)
        findings = checker.check([_url(server)])
    finally:
        server.shutdown()
        server.server_close()
    assert [f.check for f in findings] == ["smuggle-te-cl"]


def test_hardened_backend_silent():
    server = _serve(_HardenedHandler)
    try:
        checker = SmuggleChecker(connect_timeout=2, read_timeout=2)
        findings = checker.check([_url(server)])
    finally:
        server.shutdown()
        server.server_close()
    assert findings == []


def test_dead_target_no_findings():
    checker = SmuggleChecker(connect_timeout=1, read_timeout=1)
    assert checker.check(["http://127.0.0.1:1/smuggle"]) == []


def test_https_skipped():
    checker = SmuggleChecker()
    assert checker.check(["https://lab.invalid/smuggle"]) == []


def test_findings_carry_reporting_metadata():
    server = _serve(_VulnTeclHandler)
    try:
        checker = SmuggleChecker(connect_timeout=2, read_timeout=2)
        findings = checker.check([_url(server)])
    finally:
        server.shutdown()
        server.server_close()
    assert findings
    for finding in findings:
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1
