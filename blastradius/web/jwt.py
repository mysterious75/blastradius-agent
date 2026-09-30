"""Live JWT checking for the dynamic web scanner.

The static engine flags weak JWT verification in source; this module tests a
**running** target's token handling:

* **alg:none** — re-encode a captured token with ``{"alg":"none"}`` and an empty
  signature; if the target still accepts it, signature verification is missing.
* **RS256 -> HS256 confusion** — if a JWKS/public key is exposed, re-sign the
  token with HS256 using the public key as the HMAC secret; acceptance means
  the verifier mixes key types (Titan-class bug).
* **Weak HMAC secret** — try a small dictionary of common secrets against an
  HS256 token.
* **Structural hygiene** — no ``exp`` (non-expiring), ``kid`` path-traversal /
  injection characters, and ``jku``/``x5u`` pointing off-host.

All checks take a ``send(token) -> response`` callable so they are offline-testable
(the test supplies a fake verifier). No external network is required.
"""

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

# A short, high-signal dictionary of weak HMAC secrets seen in the wild.
WEAK_SECRETS = (
    "secret", "password", "123456", "changeme", "admin", "jwt", "key",
    "your-256-bit-secret", "supersecret", "test", "dev", "private",
)
_KID_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/|%2f|%5c|\x00)")


@dataclass
class JwtFinding:
    """A live JWT finding."""

    url: str
    check: str  # jwt-none | jwt-confusion | jwt-weak-secret | jwt-hygiene
    severity: str
    cwe: str
    confidence: float
    evidence: str
    remediation: str
    description: str = ""


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> Optional[Tuple[dict, dict, str]]:
    """Return (header, payload, signature) or None if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts[2]


def forge_none(token: str) -> Optional[str]:
    """Re-encode a JWT with ``alg:none`` and an empty signature."""
    decoded = decode_jwt(token)
    if decoded is None:
        return None
    header, payload, _ = decoded
    header = dict(header)
    header["alg"] = "none"
    return f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}." \
           f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}."


def forge_hs256(token: str, secret: bytes) -> Optional[str]:
    """Re-sign a JWT with HS256 using ``secret`` (for confusion / weak-secret tests)."""
    decoded = decode_jwt(token)
    if decoded is None:
        return None
    header, payload, _ = decoded
    header = dict(header)
    header["alg"] = "HS256"
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


class JwtChecker:
    """Run live JWT acceptance tests via a caller-supplied ``send`` function."""

    def __init__(
        self,
        send: Callable[[str], object],
        url: str = "",
        jwks_public_key: Optional[bytes] = None,
        weak_secrets: Tuple[str, ...] = WEAK_SECRETS,
    ):
        self.send = send
        self.url = url
        self.jwks_public_key = jwks_public_key
        self.weak_secrets = weak_secrets

    def check(self, token: str) -> List[JwtFinding]:
        findings: List[JwtFinding] = []
        decoded = decode_jwt(token)
        if decoded is None:
            return findings
        header, payload, _ = decoded

        # ---- alg:none ----
        forged = forge_none(token)
        if forged and self._accepted(forged):
            findings.append(self._mk(
                "jwt-none", "CRITICAL", "CWE-347", 0.97,
                "token with alg=none and empty signature was accepted",
                "Reject alg=none; verify the signature with an explicit, fixed algorithm allowlist."))

        # ---- RS256 -> HS256 confusion ----
        if self.jwks_public_key is not None:
            forged = forge_hs256(token, self.jwks_public_key)
            if forged and self._accepted(forged):
                findings.append(self._mk(
                    "jwt-confusion", "CRITICAL", "CWE-347", 0.95,
                    "RS256->HS256 confusion: token signed with the public key as HMAC secret accepted",
                    "Pin the algorithm; never derive the HMAC secret from an asymmetric public key."))

        # ---- weak HMAC secret ----
        if str(header.get("alg", "")).upper().startswith("HS"):
            for secret in self.weak_secrets:
                forged = forge_hs256(token, secret.encode())
                if forged and self._accepted(forged):
                    findings.append(self._mk(
                        "jwt-weak-secret", "HIGH", "CWE-798", 0.9,
                        f"HS256 token re-signed with weak secret {secret!r} was accepted",
                        "Use a long random secret and rotate it; prefer asymmetric signing."))
                    break

        # ---- hygiene ----
        if "exp" not in payload:
            findings.append(self._mk(
                "jwt-hygiene", "LOW", "CWE-613", 0.9,
                "token has no exp claim (never expires)",
                "Always set a short exp and validate it server-side."))
        kid = header.get("kid")
        if isinstance(kid, str) and _KID_TRAVERSAL.search(kid):
            findings.append(self._mk(
                "jwt-hygiene", "HIGH", "CWE-22", 0.85,
                f"kid contains traversal/injection characters: {kid!r}",
                "Never use kid in file paths or queries; map it to a key via an allowlist."))
        for hdr in ("jku", "x5u"):
            val = header.get(hdr)
            if isinstance(val, str) and re.match(r"^https?://", val):
                findings.append(self._mk(
                    "jwt-hygiene", "MEDIUM", "CWE-918", 0.7,
                    f"{hdr} points to a remote URL ({val}); verify host allowlisting",
                    f"Only honour {hdr} for explicitly allowlisted hosts."))
        return findings

    # ------------------------------------------------------------------
    def _accepted(self, token: str) -> bool:
        try:
            resp = self.send(token)
        except Exception:
            return False
        status = getattr(resp, "status", None)
        return status is not None and 200 <= status < 300

    def _mk(self, check, severity, cwe, confidence, evidence, remediation) -> JwtFinding:
        return JwtFinding(url=self.url, check=check, severity=severity, cwe=cwe,
                          confidence=confidence, evidence=evidence, remediation=remediation,
                          description="Live JWT acceptance test.")
