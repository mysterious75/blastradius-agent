"""Offline tests for the live JWT checker (fake verifier, no network)."""

import base64
import hashlib
import hmac
import json

from blastradius.web.jwt import (
    JwtChecker,
    decode_jwt,
    forge_none,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(header, payload, secret=b"real-secret", alg="HS256"):
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


class Resp:
    def __init__(self, status):
        self.status = status


def verifier_none_enabled(token):
    """Accept anything (vulnerable to alg:none)."""
    return Resp(200)


def verifier_strict(token):
    """Only accept tokens signed with the real secret."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return Resp(401)
    expected = hmac.new(b"real-secret", f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    try:
        got = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except Exception:
        return Resp(401)
    return Resp(200 if hmac.compare_digest(expected, got) else 401)


def test_decode_and_forge_none():
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    assert decode_jwt(tok) is not None
    forged = forge_none(tok)
    assert forged.endswith(".") and decode_jwt(forged)[0]["alg"] == "none"


def test_detects_alg_none():
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    c = JwtChecker(send=verifier_none_enabled, url="https://app.test/me")
    checks = {f.check for f in c.check(tok)}
    assert "jwt-none" in checks


def test_strict_verifier_no_none_finding():
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    c = JwtChecker(send=verifier_strict)
    checks = {f.check for f in c.check(tok)}
    assert "jwt-none" not in checks


def test_detects_weak_secret():
    tok = make_jwt(
        {"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, secret=b"secret"
    )

    def verifier(token):
        # accepts only tokens signed with the weak secret "secret"
        parts = token.split(".")
        sig = hmac.new(b"secret", f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        got = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        return Resp(200 if hmac.compare_digest(sig, got) else 401)

    c = JwtChecker(send=verifier)
    checks = {f.check for f in c.check(tok)}
    assert "jwt-weak-secret" in checks


def test_detects_rs256_hs256_confusion():
    pub = b"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n"
    tok = make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})

    def verifier(token):
        # naive verifier uses the public key bytes as the HMAC secret
        parts = token.split(".")
        sig = hmac.new(pub, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        try:
            got = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        except Exception:
            return Resp(401)
        return Resp(200 if hmac.compare_digest(sig, got) else 401)

    c = JwtChecker(send=verifier, jwks_public_key=pub)
    checks = {f.check for f in c.check(tok)}
    assert "jwt-confusion" in checks


def test_hygiene_no_exp():
    tok = make_jwt({"alg": "HS256"}, {"sub": "1"})
    c = JwtChecker(send=verifier_strict)
    checks = {f.check for f in c.check(tok)}
    assert "jwt-hygiene" in checks


def test_hygiene_kid_traversal():
    tok = make_jwt({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "1", "exp": 1})
    c = JwtChecker(send=verifier_strict)
    ev = [f.evidence for f in c.check(tok) if f.check == "jwt-hygiene"]
    assert any("traversal" in e for e in ev)


def test_non_jwt_returns_empty():
    c = JwtChecker(send=verifier_none_enabled)
    assert c.check("not-a-jwt") == []
