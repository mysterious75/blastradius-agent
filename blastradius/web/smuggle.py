"""Live HTTP request-smuggling checks for the dynamic web scanner.

Methodology follows James Kettle's desync canon (PortSwigger research),
restricted to the two SAFE detection probes — no poisoning, no victim
requests, everything stays on our own connection:

1. **CL.TE timing probe** (run FIRST — ordering matters): an ambiguous
   request with ``Content-Length: 4`` + ``Transfer-Encoding: chunked`` and
   an invalid chunk (``1\\r\\nZ\\r\\nQ``). A synchronized pair answers fast
   (or rejects); a CL-front/TE-back pair leaves the backend waiting for a
   valid chunk, which surfaces as a read timeout against a fast baseline.
2. **TE.CL differential probe** (run ONLY when the CL.TE probe is negative —
   in Kettle's ordering this probe would poison a CL.TE backend, so the
   sequence is load-bearing): ``Content-Length: 6`` + chunked ``0\\r\\n\\r\\nX``
   followed by a normal request on the SAME connection. A TE-front/CL-back
   pair treats the stray ``X`` as the next request, so our own follow-up
   visibly desyncs (404/unrecognized instead of the baseline answer).

Raw sockets are required: no HTTP client library will emit ambiguous
framing on purpose. Every socket carries explicit connect/read timeouts
(the net-scanner discipline), probes are inert bytes (``X``/``Q`` draw a
400/404 on our own follow-up at worst), and depth/DoS variants, H2
downgrade, and any victim-request confirmation are deliberately out of
scope — a differential on our own connection is the finding.

Findings are candidates: a desync primitive is proven, exploitability
(session hijack, ACL bypass — cf. CVE-2026-2835/6338/69243) is not.
"""

import contextlib
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional, Tuple

#: Kettle's CL.TE timing probe: front (CL:4) forwards 4 bytes; back (TE)
#: waits for a valid chunk that never comes.
_CLTE_BODY = b"1\r\nZ\r\nQ"
_CLTE_LENGTH = 4

#: Kettle's TE.CL differential probe: front (TE) forwards through the
#: terminating 0-chunk; back (CL:6) keeps the stray X as the next request.
_TECL_BODY = b"0\r\n\r\nX"
_TECL_LENGTH = 6

_DESYNC_STATUS = re.compile(rb"^HTTP/[\d.]+\s+(404|400|501|505)\b")


@dataclass
class SmuggleFinding:
    """A live request-smuggling candidate finding."""

    url: str
    check: str  # smuggle-cl-te | smuggle-te-cl
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def build_clte_probe(host: str, path: str) -> bytes:
    """The ambiguous CL.TE timing probe (pure function, unit-tested)."""
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {_CLTE_LENGTH}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + _CLTE_BODY


def build_tecl_probe(host: str, path: str) -> bytes:
    """The ambiguous TE.CL differential probe (pure function, unit-tested)."""
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {_TECL_LENGTH}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode() + _TECL_BODY


def build_followup(host: str, path: str) -> bytes:
    """Normal follow-up for the SAME path on the same connection.

    The path must answer 200 when synchronized (mirroring the PortSwigger
    labs, where the follow-up is GET /): a desynced backend answers the
    stray X instead, visibly changing the status.
    """
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()


class SmuggleChecker:
    """Kettle-ordered desync probes over raw sockets with strict timeouts."""

    def __init__(
        self,
        connect_timeout: float = 3.0,
        read_timeout: float = 4.0,
        baseline_ceiling: float = 1.0,
    ):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.baseline_ceiling = baseline_ceiling

    # ------------------------------------------------------------------
    def check(self, urls: List[str]) -> List[SmuggleFinding]:
        findings: List[SmuggleFinding] = []
        for url in urls:
            findings.extend(self._check_url(url))
        return findings

    def _check_url(self, url: str) -> List[SmuggleFinding]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.scheme == "https":
            return []  # raw-socket probes are HTTP/1.1 only; no TLS smuggling here
        host = parsed.hostname or ""
        port = parsed.port or 80
        path = parsed.path or "/"
        if not host:
            return []
        baseline = self._baseline(host, port, path)
        if baseline is None:
            return []
        if self._probe_clte(host, port, path, baseline):
            return [
                SmuggleFinding(
                    url=url,
                    check="smuggle-cl-te",
                    severity="HIGH",
                    cwe="CWE-444",
                    confidence=0.8,
                    evidence=(
                        f"ambiguous CL:4/TE-chunked probe timed out "
                        f"({baseline:.2f}s baseline vs read-timeout wait)"
                    )[:500],
                    remediation="Normalize framing at the edge: reject requests "
                    "with both Content-Length and Transfer-Encoding, enforce "
                    "RFC 9112 framing, and never let front and back disagree.",
                    description="Live CL.TE desync probe: backend waited for a chunk.",
                )
            ]
        # Kettle ordering: TE.CL probe only when CL.TE is ruled out.
        if self._probe_tecl(host, port, path):
            return [
                SmuggleFinding(
                    url=url,
                    check="smuggle-te-cl",
                    severity="HIGH",
                    cwe="CWE-444",
                    confidence=0.8,
                    evidence=(
                        "ambiguous CL:6/TE-chunked probe desynced our own "
                        "follow-up (stray X consumed as a request)"
                    )[:500],
                    remediation="Normalize framing at the edge: reject requests "
                    "with both Content-Length and Transfer-Encoding, enforce "
                    "RFC 9112 framing, and never let front and back disagree.",
                    description="Live TE.CL desync probe: follow-up visibly desynced.",
                )
            ]
        return []

    # ------------------------------------------------------------------
    def _baseline(self, host: str, port: int, path: str) -> Optional[float]:
        """Time a normal POST; None when the target is unusable/slow."""
        payload = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Length: 7\r\nConnection: close\r\n\r\nq=probe"
        ).encode()
        response, elapsed = self._exchange(host, port, payload)
        if not response or elapsed > self.baseline_ceiling:
            return None
        return elapsed

    def _probe_clte(self, host: str, port: int, path: str, baseline: float) -> bool:
        """True when the ambiguous probe hangs against a fast baseline."""
        _, elapsed = self._exchange(host, port, build_clte_probe(host, path))
        # No response within the read timeout while the baseline was fast:
        # the backend is waiting for a valid chunk (CL.TE).
        return elapsed >= self.read_timeout

    def _probe_tecl(self, host: str, port: int, path: str) -> bool:
        """True when our own follow-up is visibly desynced by the stray X.

        The probe's own answer (R1) is drained first: a hardened server may
        legitimately 400 the ambiguous framing itself, and that must never
        count — only the FOLLOW-UP's corruption is the signal.
        """
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=self.connect_timeout)
            sock.settimeout(self.read_timeout)
            sock.sendall(build_tecl_probe(host, path))
            self._read_first(sock)  # drain R1 (whatever the probe itself drew)
            time.sleep(0.3)  # let the backend frame the stray X as a request
            sock.sendall(build_followup(host, path))
            followup = self._read_first(sock)
        except Exception:
            return False
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()
        return bool(_DESYNC_STATUS.search(followup))

    # ------------------------------------------------------------------
    def _exchange(self, host: str, port: int, payload: bytes) -> Tuple[bytes, float]:
        """Send payload, wait for the FIRST response bytes; return (bytes, seconds).

        First-bytes timing is the signal: a synchronized server answers (or
        rejects) promptly; a desynced backend sends nothing until the read
        timeout fires. Reading to close would conflate "fast answer on a
        keep-alive connection" with "backend waiting" — a false positive.
        """
        sock = None
        start = time.monotonic()
        try:
            sock = socket.create_connection((host, port), timeout=self.connect_timeout)
            sock.settimeout(self.read_timeout)
            sock.sendall(payload)
            return self._read_first(sock), time.monotonic() - start
        except Exception:
            return b"", time.monotonic() - start
        finally:
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()

    def _read_first(self, sock: socket.socket) -> bytes:
        """First response bytes only: desync signals live in the head.

        (Never read-to-close here: a keep-alive server that answers promptly
        but never closes would look identical to a backend waiting for a
        chunk — a guaranteed false positive.)
        """
        try:
            return sock.recv(4096)
        except (socket.timeout, TimeoutError):
            return b""
