"""Live authorization-diff (IDOR/BOLA) check — offline tests.

Uses a fake BrowserSession-like object (duck-typed .get()) so no network is
touched. Mirrors the repo policy: offline, deterministic, no real requests.
"""

from blastradius.web.authz import AuthzDiffChecker
from blastradius.web.browser import BrowserSession, Page
from blastradius.web.scanner import DynamicWebScanner


class FakeSession:
    """Duck-typed session: maps url -> Page (or raises)."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, params=None):
        self.calls.append(url)
        resp = self.responses.get(url)
        if resp is None:
            raise RuntimeError("no route")
        status, body = resp
        return Page(url=url, status=status, headers={}, text=body)


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------

def test_candidate_url_detection():
    assert AuthzDiffChecker.is_candidate_url("https://x.test/api/users/1234")
    assert AuthzDiffChecker.is_candidate_url("https://x.test/doc/01a0aced-1f5e-7204-97c4-2e0be2907656")
    assert AuthzDiffChecker.is_candidate_url("https://x.test/api?user_id=7")
    assert AuthzDiffChecker.is_candidate_url("https://x.test/invoices?invoice=99")
    assert not AuthzDiffChecker.is_candidate_url("https://x.test/about")
    assert not AuthzDiffChecker.is_candidate_url("https://x.test/search?q=hello")


def test_candidate_urls_bounded_and_deduped():
    c = AuthzDiffChecker(attacker=FakeSession({}), victim=FakeSession({}), max_probes=2)
    urls = ["/api/u/1", "/api/u/2", "/api/u/3", "/about", "/api/u/1"]
    out = c.candidate_urls(urls)
    assert out == ["/api/u/1", "/api/u/2"]


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------

def test_disabled_without_both_sessions():
    assert AuthzDiffChecker().enabled is False
    assert AuthzDiffChecker(attacker=FakeSession({})).enabled is False
    assert AuthzDiffChecker(attacker=FakeSession({}), victim=FakeSession({})).enabled is True
    assert AuthzDiffChecker(attacker=FakeSession({}), victim=FakeSession({})).check(["/x/1"]) == []


def test_confirms_cross_identity_read_with_markers():
    url = "/api/users/1234"
    victim = FakeSession({url: (200, '{"email":"victim@corp.test","ssn":"111-22-3333"}')})
    attacker = FakeSession({url: (200, '{"email":"victim@corp.test","ssn":"111-22-3333"}')})
    c = AuthzDiffChecker(attacker=attacker, victim=victim, victim_markers=["victim@corp.test"])
    hits = c.check([url])
    assert len(hits) == 1
    hit = hits[0]
    assert hit.check == "idor" and hit.cwe == "CWE-639" and hit.confidence == 0.95
    assert "victim@corp.test" in hit.evidence


def test_no_hit_when_attacker_is_denied():
    url = "/api/users/1234"
    victim = FakeSession({url: (200, '{"email":"victim@corp.test"}')})
    attacker = FakeSession({url: (403, '{"error":"forbidden"}')})
    c = AuthzDiffChecker(attacker=attacker, victim=victim, victim_markers=["victim@corp.test"])
    assert c.check([url]) == []


def test_no_hit_when_attacker_body_is_denial_variant():
    url = "/api/users/1234"
    victim = FakeSession({url: (200, "victim secret data")})
    attacker = FakeSession({url: (200, "Access Denied")})
    c = AuthzDiffChecker(attacker=attacker, victim=victim, victim_markers=["victim secret data"])
    assert c.check([url]) == []


def test_no_hit_when_victim_own_response_is_denial():
    url = "/api/users/9999"
    victim = FakeSession({url: (200, "not found")})
    attacker = FakeSession({url: (200, "not found")})
    c = AuthzDiffChecker(attacker=attacker, victim=victim)
    assert c.check([url]) == []


def test_identical_body_without_markers_is_lower_confidence():
    url = "/api/users/1234"
    victim = FakeSession({url: (200, "same-content")})
    attacker = FakeSession({url: (200, "same-content")})
    c = AuthzDiffChecker(attacker=attacker, victim=victim)  # no markers
    hits = c.check([url])
    assert len(hits) == 1 and hits[0].confidence == 0.75


def test_different_body_without_markers_is_not_flagged():
    url = "/api/users/1234"
    victim = FakeSession({url: (200, "victim-content")})
    attacker = FakeSession({url: (200, "attacker-content")})
    c = AuthzDiffChecker(attacker=attacker, victim=victim)  # no markers
    assert c.check([url]) == []


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------

def test_scanner_runs_authz_when_enabled():
    url = "/api/orders/555"
    victim = FakeSession({url: (200, '{"total":42,"buyer":"vip"}')})
    attacker = FakeSession({url: (200, '{"total":42,"buyer":"vip"}')})
    authz = AuthzDiffChecker(attacker=attacker, victim=victim, victim_markers=["vip"])
    scanner = DynamicWebScanner(probe_exposed=False, check_takeover=False, authz=authz)
    findings = scanner._check_authz([url])
    assert len(findings) == 1
    assert findings[0].check == "idor"


def test_scanner_without_authz_is_inert():
    scanner = DynamicWebScanner(probe_exposed=False, check_takeover=False)
    assert scanner._check_authz(["/api/orders/555"]) == []


def test_browser_session_default_headers_reach_request():
    # default_headers must be merged into every request (used by IDOR CLI).
    s = BrowserSession(default_headers={"Cookie": "session=abc"})
    assert s.default_headers == {"Cookie": "session=abc"}


def test_scanner_uses_explicit_authz_urls():
    # Explicit --idor-url candidates are tested even if the crawler found none.
    url = "/api/user/2"
    victim = FakeSession({url: (200, '{"email":"victim@corp.test"}')})
    attacker = FakeSession({url: (200, '{"email":"victim@corp.test"}')})
    authz = AuthzDiffChecker(attacker=attacker, victim=victim, victim_markers=["victim@corp.test"])
    scanner = DynamicWebScanner(probe_exposed=False, check_takeover=False, authz=authz,
                                authz_urls=[url])
    findings = scanner._check_authz(scanner.authz_urls)
    assert len(findings) == 1 and findings[0].check == "idor"
