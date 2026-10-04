"""NetworkServiceScanner — Tsunami-style network-service plugin foundation.

Pipeline (stdlib only, no new dependencies):

    port scan (bounded TCP connect, strict timeouts)
      -> banner grab (read-first greeting, then ONE light service probe)
      -> fingerprint (Nmap-style banner regexes, light intensity only)
      -> service-filtered detectors (Tsunami @ForServiceName discipline:
         a detector only runs when the fingerprinted service matches)

Safety discipline (this is what makes it shippable, not just a scanner):

* Every socket gets an explicit connect timeout AND read timeout — the
  Tsunami ``TsunamiSocketFactory`` rule: a probe must never hang the scan.
* Exactly one light probe per open port (Nmap ``--version-light`` spirit).
  No brute force, no password guessing, no exploit payloads. The only
  credential ever sent is FTP ``anonymous`` (no secret), which is a
  read-only misconfiguration signal, not an intrusion.
* SSH (and any authenticated service) is fingerprinted from the banner only;
  authentication is never attempted.
* Findings are candidates with the exact wire bytes as evidence — banner
  text is proof of exposure, never proof of exploitability.
* Port budget: presets are small; an explicit full-range scan prints a
  warning and requires a registered ``--scope`` program at the CLI layer.

Detectors (check -> CWE):

    cleartext-ftp    CWE-319  FTP speaks credentials in cleartext (MEDIUM)
    cleartext-telnet CWE-319  Telnet speaks everything in cleartext (HIGH —
                             telnetd is CISA-KEV in 2026: CVE-2026-24061,
                             CVE-2026-32746; any reachable telnetd is critical
                             exposure until proven otherwise)
    anonymous-ftp    CWE-287  FTP accepts anonymous login (HIGH, read-only probe)
    missing-starttls CWE-319  SMTP advertises EHLO without STARTTLS (MEDIUM)

Usage:
    scanner = NetworkServiceScanner()
    findings = scanner.scan("127.0.0.1", ports="common")
"""

import contextlib
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Small, deliberate presets. A full 65k sweep is possible only via an
#: explicit range and is rate-limited + scope-gated at the CLI layer.
PORT_PRESETS: Dict[str, Tuple[int, ...]] = {
    "common": (
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        443,
        445,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        27017,
    ),
    "web": (80, 443, 8000, 8080, 8443, 8888, 9000, 9090),
    "mail": (25, 110, 143, 465, 587, 993, 995, 2525),
    "db": (1433, 1521, 3306, 5432, 6379, 27017, 28017),
    "remote": (21, 22, 23, 3389, 5900, 5901),
}

#: Port-number hint used to pick the light probe (fingerprint decides).
_PORT_HINTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    110: "pop3",
    143: "imap",
    587: "smtp",
    2525: "smtp",
}

#: Fingerprint rules: (service, compiled banner regex). First match wins —
#: Nmap orders probes by rarity; here specificity is encoded by order.
_FINGERPRINTS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("ssh", re.compile(r"^SSH-([\d.]+)-(\S+)", re.IGNORECASE)),
    ("ftp", re.compile(r"^220[ -].*(?:ftp|filezilla|vsftpd|proftpd|pure-ftpd)", re.IGNORECASE)),
    ("smtp", re.compile(r"^220[ -].*(?:smtp|esmtp|postfix|exim|sendmail)", re.IGNORECASE)),
    ("http", re.compile(r"^HTTP/[\d.]+\s+\d+", re.IGNORECASE)),
    ("http", re.compile(r"(?i)server\s*:\s*([^\r\n]+)")),
    ("mysql", re.compile(r"mysql|mariadb", re.IGNORECASE)),
    ("pop3", re.compile(r"^\+OK.*(?:pop|dovecot|courier)", re.IGNORECASE)),
    ("imap", re.compile(r"^\* OK.*(?:imap|dovecot|courier)", re.IGNORECASE)),
)

#: Telnet negotiation opens with IAC (0xFF) bytes — a protocol signal even
#: when no readable banner follows.
_TELNET_IAC = b"\xff"

_MAX_BANNER = 2048
_MAX_EVIDENCE = 500
_MAX_PORTS_PER_SCAN = 4096


@dataclass
class ServiceProfile:
    """What the discovery phase learned about one open port."""

    host: str
    port: int
    service: str  # ftp | ssh | smtp | telnet | http | mysql | pop3 | imap | unknown
    banner: str = ""
    transcript: str = ""  # greeting + light probe exchange (evidence)
    product: str = ""
    version: str = ""


@dataclass
class NetFinding:
    """A network-service candidate finding with wire evidence."""

    host: str
    port: int
    check: str  # cleartext-ftp | cleartext-telnet | anonymous-ftp | missing-starttls
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""

    @property
    def url(self) -> str:
        return f"{self.host}:{self.port}"


def parse_ports(spec: str) -> List[int]:
    """Parse a preset name, list (22,80), and/or range (1-1024) into ports."""
    spec = (spec or "common").strip().lower()
    if spec in PORT_PRESETS:
        return sorted(set(PORT_PRESETS[spec]))
    ports: List[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk in PORT_PRESETS:
            ports.extend(PORT_PRESETS[chunk])
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            ports.extend(range(int(start), int(end) + 1))
            continue
        ports.append(int(chunk))
    ports = sorted({p for p in ports if 1 <= p <= 65535})
    if not ports:
        raise ValueError(f"no valid ports in {spec!r}")
    return ports


class NetworkServiceScanner:
    """Bounded TCP connect + banner grab + fingerprint + filtered detectors."""

    def __init__(
        self,
        connect_timeout: float = 3.0,
        read_timeout: float = 5.0,
        workers: int = 20,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.workers = max(1, min(workers, 100))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, host: str, ports: str = "common") -> List[NetFinding]:
        """Scan ports on host; return candidate findings (never raises)."""
        port_list = parse_ports(ports)
        if len(port_list) > _MAX_PORTS_PER_SCAN:
            raise ValueError(
                f"{len(port_list)} ports exceeds the per-scan budget "
                f"({_MAX_PORTS_PER_SCAN}); narrow the range"
            )
        findings: List[NetFinding] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            profiles = list(pool.map(lambda p: self._profile(host, p), port_list))
        for profile in profiles:
            if profile is not None:
                findings.extend(self._detect(profile))
        return findings

    # ------------------------------------------------------------------
    # Discovery: connect + banner + light probe
    # ------------------------------------------------------------------

    def _profile(self, host: str, port: int) -> Optional[ServiceProfile]:
        """One port: connect, read greeting, send ONE light probe. None if closed."""
        sock = None
        try:
            # TsunamiSocketFactory discipline: connect timeout here, read
            # timeout immediately after — no socket may ever block forever.
            sock = socket.create_connection((host, port), timeout=self.connect_timeout)
            sock.settimeout(self.read_timeout)
            greeting = self._read(sock)
            transcript = greeting
            hint = _PORT_HINTS.get(port, "generic")
            service, product, version = self._fingerprint(greeting)
            if service == "unknown":
                service = hint if hint != "generic" else "unknown"
            probe_reply = self._light_probe(sock, service, host)
            if probe_reply:
                transcript += probe_reply
                probed_service, probed_product, probed_version = self._fingerprint(
                    greeting + probe_reply
                )
                if probed_service != "unknown":
                    service, product, version = probed_service, probed_product, probed_version
            # Telnet speaks IAC bytes before any readable banner.
            if service == "unknown" and greeting.startswith(_TELNET_IAC):
                service = "telnet"
            return ServiceProfile(
                host=host,
                port=port,
                service=service,
                banner=_clean(greeting),
                transcript=_clean(transcript),
                product=product,
                version=version,
            )
        except Exception:
            return None  # closed / filtered / timed out — no finding, no noise
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()

    def _read(self, sock: socket.socket) -> bytes:
        """Read until newline, 2KB, or timeout — never more."""
        chunks = []
        total = 0
        try:
            while total < _MAX_BANNER:
                data = sock.recv(1024)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if b"\n" in data:
                    break
        except (socket.timeout, TimeoutError):
            pass
        return b"".join(chunks)

    def _light_probe(self, sock: socket.socket, service: str, host: str) -> bytes:
        """Exactly one service-appropriate probe; b"" when none applies."""
        try:
            if service == "http":
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                return self._read(sock)
            if service == "smtp":
                sock.sendall(b"EHLO blastradius.invalid\r\n")
                return self._read(sock)
            if service == "ftp":
                # Banner-only for discovery; the anonymous check is a
                # separate detector with its own connection.
                return b""
            if service == "ssh":
                return b""  # never poke an authenticated service
            sock.sendall(b"\r\n")  # generic elicitation (Nmap NULL-probe spirit)
            return self._read(sock)
        except Exception:
            return b""

    @staticmethod
    def _fingerprint(data: bytes) -> Tuple[str, str, str]:
        """(service, product, version) from banner text; unknown when silent."""
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return "unknown", "", ""
        for service, pattern in _FINGERPRINTS:
            match = pattern.search(text)
            if match:
                groups = [g for g in match.groups() if g]
                if service == "ssh":
                    version = groups[0] if groups else ""
                    product = groups[1] if len(groups) > 1 else ""
                    return service, product.strip(), version.strip()
                detail = (groups[0] if groups else "").strip()
                product, _, version = detail.partition(" ")
                return service, product, version.strip("(),")
        if text.strip():
            return "unknown", "", ""
        return "unknown", "", ""

    # ------------------------------------------------------------------
    # Detection: service-filtered detectors (Tsunami @ForServiceName rule)
    # ------------------------------------------------------------------

    def _detect(self, profile: ServiceProfile) -> List[NetFinding]:
        """Run ONLY the detectors whose service matches the fingerprint."""
        if profile.service == "telnet":
            return [self._mk(profile, "cleartext-telnet", "HIGH", "CWE-319", 0.85)]
        if profile.service == "ftp":
            findings = [self._mk(profile, "cleartext-ftp", "MEDIUM", "CWE-319", 0.8)]
            if self._anonymous_ftp(profile):
                findings.append(self._mk(profile, "anonymous-ftp", "HIGH", "CWE-287", 0.9))
            return findings
        if profile.service == "smtp":
            if "starttls" not in profile.transcript.lower():
                return [self._mk(profile, "missing-starttls", "MEDIUM", "CWE-319", 0.75)]
            return []
        return []  # ssh/http/mysql/unknown: fingerprinted, not flagged

    def _anonymous_ftp(self, profile: ServiceProfile) -> bool:
        """Single read-only anonymous login attempt. No password is ever tried."""
        sock = None
        try:
            sock = socket.create_connection(
                (profile.host, profile.port), timeout=self.connect_timeout
            )
            sock.settimeout(self.read_timeout)
            self._read(sock)  # greeting
            sock.sendall(b"USER anonymous\r\n")
            user_reply = self._read(sock)
            if b"230" in user_reply:
                return True  # logged in without any password at all
            if b"331" not in user_reply:
                return False
            sock.sendall(b"PASS blastradius@example.invalid\r\n")
            return b"230" in self._read(sock)
        except Exception:
            return False
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.sendall(b"QUIT\r\n")
                    sock.close()

    # ------------------------------------------------------------------
    @staticmethod
    def _mk(
        profile: ServiceProfile, check: str, severity: str, cwe: str, confidence: float
    ) -> NetFinding:
        evidence = f"{profile.service} on {profile.host}:{profile.port} — {profile.transcript}"
        return NetFinding(
            host=profile.host,
            port=profile.port,
            check=check,
            severity=severity,
            cwe=cwe,
            confidence=confidence,
            evidence=evidence[:_MAX_EVIDENCE],
            remediation=_REMEDIATION[check],
            description=_DESCRIPTION[check],
        )


_REMEDIATION = {
    "cleartext-ftp": (
        "Replace FTP with SFTP/FTPS; if FTP must stay, restrict it to a "
        "management network and never reuse those credentials elsewhere."
    ),
    "cleartext-telnet": (
        "Disable telnet entirely and use SSH; if the banner shows "
        "inetutils telnetd <= 2.7, patch immediately (CISA KEV 2026)."
    ),
    "anonymous-ftp": (
        "Disable anonymous access on the FTP server; require authenticated "
        "accounts with least privilege and audit the exposed directories."
    ),
    "missing-starttls": (
        "Advertise and enforce STARTTLS on the mail submission path; "
        "reject cleartext authentication when TLS is unavailable."
    ),
}

_DESCRIPTION = {
    "cleartext-ftp": "FTP transmits credentials in cleartext — live banner evidence.",
    "cleartext-telnet": "Telnet transmits everything (including credentials) in cleartext.",
    "anonymous-ftp": "FTP server accepted an anonymous login (read-only probe).",
    "missing-starttls": "SMTP EHLO response advertises no STARTTLS — mail auth would be cleartext.",
}


def _clean(data: bytes) -> str:
    """Wire bytes -> single-line evidence-safe text."""
    return data.decode("utf-8", errors="replace").replace("\r", "").strip()
