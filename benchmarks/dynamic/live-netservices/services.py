"""Fake network services for the live-netservices benchmark target.

Three deliberately misconfigured services plus one negative control, all on
127.0.0.1 ephemeral ports:

* FTP  — vsFTPd-style greeting, anonymous login accepted  -> cleartext-ftp + anonymous-ftp
* SMTP — Postfix-style greeting, EHLO without STARTTLS    -> missing-starttls
* Telnet — IAC negotiation bytes                          -> cleartext-telnet
* SSH  — OpenSSH banner, silence afterwards (authenticated service: fingerprinted,
  never flagged)                                          -> no finding (FP guard)
"""

import socketserver
import threading


class _QuietTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def _read_line(request):
    buf = b""
    request.settimeout(2)
    try:
        while not buf.endswith(b"\n") and len(buf) < 512:
            chunk = request.recv(128)
            if not chunk:
                break
            buf += chunk
    except Exception:
        pass
    return buf.decode("utf-8", errors="replace")


class FtpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"220 (vsFTPd 3.0.3) ready.\r\n")
        if _read_line(self.request).startswith("USER anonymous"):
            self.request.sendall(b"230 Login successful.\r\n")
        else:
            self.request.sendall(b"530 Login incorrect.\r\n")


class SmtpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"220 mail.example.invalid ESMTP Postfix\r\n")
        if _read_line(self.request).startswith("EHLO"):
            self.request.sendall(b"250-mail.example.invalid\r\n250-8BITMIME\r\n250 DSN\r\n")


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"\xff\xfd\x18\xff\xfd\x20login: ")


class SshHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")


def make_servers():
    """Boot all four services; return [(role, server)]. Caller shuts down."""
    specs = [
        ("ftp", FtpHandler),
        ("smtp", SmtpHandler),
        ("telnet", TelnetHandler),
        ("ssh", SshHandler),
    ]
    servers = []
    for role, handler in specs:
        server = _QuietTCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.daemon = True
        thread.start()
        servers.append((role, server))
    return servers
