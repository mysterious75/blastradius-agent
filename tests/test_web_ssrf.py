"""Offline tests for the live SSRF / blind-oracle check."""

from blastradius.web.browser import Page
from blastradius.web.ssrf import SsrfChecker


class FakeListener:
    """Records markers 'hit' by a simulated server-side fetch."""

    def __init__(self, hit_markers=()):
        self.hit_markers = set(hit_markers)
        self.seen = []

    def hits_for(self, marker):
        return [marker] if marker in self.hit_markers else []


class FakeSession:
    """Injection session: on each request, optionally mark the callback as hit."""

    def __init__(self, on_request=None):
        self.on_request = on_request
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        if self.on_request:
            self.on_request(url, params or {})
        return Page(url=url, status=200, headers={}, text="")


def test_disabled_without_listener_or_base():
    assert SsrfChecker(listener=None, callback_base="http://x").enabled is False
    assert SsrfChecker(listener=FakeListener(), callback_base=None).enabled is False
    assert SsrfChecker(listener=FakeListener(), callback_base="http://x").check(["/?url=1"]) == []


def test_detects_direct_oob_ssrf():
    # The server fetches our callback URL -> listener records the marker.
    def mark(url, params):
        for v in params.values():
            if "ssrf-" in str(v):
                listener.hit_markers.add(str(v).rsplit("/", 1)[-1])

    listener = FakeListener()
    session = FakeSession(on_request=mark)
    c = SsrfChecker(listener=listener, callback_base="http://oob.test", session=session)
    hits = c.check(["https://app.test/fetch?url=https://example.com"])
    assert len(hits) == 1
    assert hits[0].check == "ssrf" and hits[0].cwe == "CWE-918" and hits[0].severity == "HIGH"


def test_no_hit_when_server_does_not_fetch():
    listener = FakeListener()  # never hit
    c = SsrfChecker(listener=listener, callback_base="http://oob.test", session=FakeSession())
    assert c.check(["https://app.test/fetch?url=https://example.com"]) == []


def test_non_url_params_ignored():
    listener = FakeListener(hit_markers=set())
    c = SsrfChecker(listener=listener, callback_base="http://oob.test", session=FakeSession())
    assert c.check(["https://app.test/search?q=hello&page=1"]) == []


def test_redirect_follow_oracle():
    listener = FakeListener()

    def mark(url, params):
        # only the redirect probe (marker ends with 'r') gets fetched
        for v in params.values():
            m = str(v).rsplit("/", 1)[-1]
            if m.endswith("r"):
                listener.hit_markers.add(m)

    session = FakeSession(on_request=mark)
    builder = lambda target: "https://redirector.test/?to=" + target
    c = SsrfChecker(listener=listener, callback_base="http://oob.test", session=session,
                    redirect_probe_builder=builder)
    hits = c.check(["https://app.test/proxy?target=https://example.com"])
    assert len(hits) == 1
    assert hits[0].check == "ssrf-oracle" and hits[0].confidence == 0.8


def test_injections_use_callback_marker():
    listener = FakeListener()
    session = FakeSession()
    c = SsrfChecker(listener=listener, callback_base="http://oob.test", session=session)
    c.check(["https://app.test/fetch?url=https://example.com"])
    assert any("oob.test" in str(v) for _, params in session.calls for v in params.values())
