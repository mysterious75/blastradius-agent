"""NetworkServiceScanner tests — fake TCP services on 127.0.0.1, offline."""

import socketserver
import threading

import pytest

from blastradius.net.scanner import (
    NetworkServiceScanner,
    parse_ports,
)


class _QuietTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def _serve(handler_cls):
    server = _QuietTCPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.daemon = True
    thread.start()
    return server


class _FakeFtp(socketserver.BaseRequestHandler):
    """vsFTPd-style greeting; anonymous allowed, named users rejected."""

    def handle(self):
        self.request.sendall(b"220 (vsFTPd 3.0.3) ready.\r\n")
        data = self._line()
        if data.startswith("USER anonymous"):
            self.request.sendall(b"230 Login successful.\r\n")
        else:
            self.request.sendall(b"530 Login incorrect.\r\n")

    def _line(self):
        buf = b""
        self.request.settimeout(2)
        try:
            while not buf.endswith(b"\n") and len(buf) < 512:
                chunk = self.request.recv(128)
                if not chunk:
                    break
                buf += chunk
        except Exception:
            pass
        return buf.decode("utf-8", errors="replace")


class _FakeSmtpNoTls(socketserver.BaseRequestHandler):
    """Postfix-style greeting; EHLO advertises 8BITMIME but no STARTTLS."""

    def handle(self):
        self.request.sendall(b"220 mail.example.invalid ESMTP Postfix\r\n")
        data = self._line()
        if data.startswith("EHLO"):
            self.request.sendall(b"250-mail.example.invalid\r\n250-8BITMIME\r\n250 DSN\r\n")

    def _line(self):
        buf = b""
        self.request.settimeout(2)
        try:
            while not buf.endswith(b"\n") and len(buf) < 512:
                chunk = self.request.recv(128)
                if not chunk:
                    break
                buf += chunk
        except Exception:
            pass
        return buf.decode("utf-8", errors="replace")


class _FakeSsh(socketserver.BaseRequestHandler):
    """OpenSSH banner, then silence — never probed further."""

    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")


class _FakeTelnet(socketserver.BaseRequestHandler):
    """IAC negotiation bytes + login prompt, like a real telnetd."""

    def handle(self):
        self.request.sendall(b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23login: ")


class _Silent(socketserver.BaseRequestHandler):
    """Accepts and says nothing — fingerprint must stay unknown, no finding."""

    def handle(self):
        self.request.settimeout(1)
        try:
            self.request.recv(64)
        except Exception:
            pass


@pytest.fixture()
def ftp_port():
    server = _serve(_FakeFtp)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def smtp_port():
    server = _serve(_FakeSmtpNoTls)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def ssh_port():
    server = _serve(_FakeSsh)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def telnet_port():
    server = _serve(_FakeTelnet)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def silent_port():
    server = _serve(_Silent)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _scan_one(port, hint_port=None):
    """Scan a single ephemeral port, forcing the service hint via portspec."""
    scanner = NetworkServiceScanner(connect_timeout=2, read_timeout=2, workers=4)
    # Bypass parse_ports presets: monkeypatch hint by scanning the real port
    # number directly — the hint map only covers well-known ports, so the
    # fingerprint must carry silent/odd-port services on its own.
    return scanner, port


# ------------------------------------------------------------- parsing


def test_parse_ports_preset():
    ports = parse_ports("web")
    assert 80 in ports and 443 in ports


def test_parse_ports_list_and_range():
    assert parse_ports("22,80") == [22, 80]
    assert parse_ports("100-102") == [100, 101, 102]


def test_parse_ports_rejects_garbage():
    with pytest.raises(ValueError):
        parse_ports("banana")


def test_scan_rejects_huge_range():
    scanner = NetworkServiceScanner()
    with pytest.raises(ValueError):
        scanner.scan("127.0.0.1", ports="1-65535")


# ------------------------------------------------------------- detectors


def test_ftp_cleartext_and_anonymous(ftp_port):
    scanner, _ = _scan_one(ftp_port)
    profile = scanner._profile("127.0.0.1", ftp_port)
    assert profile is not None
    assert profile.service == "ftp"
    assert "vsFTPd" in profile.banner
    findings = scanner._detect(profile)
    checks = {f.check for f in findings}
    assert checks == {"cleartext-ftp", "anonymous-ftp"}
    anon = [f for f in findings if f.check == "anonymous-ftp"][0]
    assert anon.severity == "HIGH"
    assert anon.cwe == "CWE-287"
    assert anon.confidence >= 0.9


def test_smtp_missing_starttls(smtp_port):
    scanner, _ = _scan_one(smtp_port)
    profile = scanner._profile("127.0.0.1", smtp_port)
    assert profile is not None
    assert profile.service == "smtp"
    findings = scanner._detect(profile)
    assert len(findings) == 1
    assert findings[0].check == "missing-starttls"
    assert findings[0].severity == "MEDIUM"


def test_ssh_fingerprinted_never_probed(ssh_port):
    scanner, _ = _scan_one(ssh_port)
    profile = scanner._profile("127.0.0.1", ssh_port)
    assert profile is not None
    assert profile.service == "ssh"
    assert "OpenSSH" in profile.product
    assert scanner._detect(profile) == []


def test_telnet_iac_detected(telnet_port):
    scanner, _ = _scan_one(telnet_port)
    profile = scanner._profile("127.0.0.1", telnet_port)
    assert profile is not None
    assert profile.service == "telnet"
    findings = scanner._detect(profile)
    assert len(findings) == 1
    assert findings[0].check == "cleartext-telnet"
    assert findings[0].severity == "HIGH"


def test_silent_service_no_finding(silent_port):
    scanner, _ = _scan_one(silent_port)
    profile = scanner._profile("127.0.0.1", silent_port)
    assert profile is not None
    assert profile.service == "unknown"
    assert scanner._detect(profile) == []


def test_closed_port_no_profile():
    scanner = NetworkServiceScanner(connect_timeout=1, read_timeout=1)
    assert scanner._profile("127.0.0.1", 1) is None  # port 1 closed in CI sandboxes


def test_scan_end_to_end_mixed(ftp_port, ssh_port):
    scanner = NetworkServiceScanner(connect_timeout=2, read_timeout=2, workers=4)
    findings = scanner.scan("127.0.0.1", ports=f"{ftp_port},{ssh_port}")
    checks = {f.check for f in findings}
    assert {"cleartext-ftp", "anonymous-ftp"} <= checks
    assert all(f.url.startswith("127.0.0.1:") for f in findings)
    assert all(f.evidence for f in findings)


def test_findings_carry_reporting_metadata(ftp_port):
    scanner = NetworkServiceScanner(connect_timeout=2, read_timeout=2)
    for finding in scanner.scan("127.0.0.1", ports=str(ftp_port)):
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1
        assert finding.port == ftp_port
