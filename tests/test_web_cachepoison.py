"""Offline tests for the live cache-poisoning checker (fake sessions, no network)."""

from blastradius.web.browser import Page
from blastradius.web.cachepoison import CachePoisonChecker, _is_cacheable


class FakeSession:
    """Simulates server behavior per test via a handler function."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def _request(self, method, url, data=None, headers=None):
        self.calls.append((method, url, dict(headers or {})))
        status, resp_headers, body = self.handler(url, dict(headers or {}))
        return Page(url=url, status=status, headers=resp_headers, text=body)


def _vuln_handler(store):
    """A cache that keys on URL only and stores reflected responses."""

    def handle(url, headers):
        marker = next((v for v in headers.values() if ".invalid" in v), None)
        if marker and url not in store:
            body = f'<html><script src="//{marker}/x.js"></script></html>'
            store[url] = body  # poisoned entry persists
            return 200, {"Cache-Control": "public, max-age=3600"}, body
        if url in store:
            return 200, {"Cache-Control": "public, max-age=3600", "Age": "5"}, store[url]
        return 200, {"Cache-Control": "public, max-age=3600"}, "<html>clean</html>"

    return handle


def test_detects_persisted_poison_in_resource_context():
    store = {}
    c = CachePoisonChecker(session=FakeSession(_vuln_handler(store)))
    hits = c.check(["https://app.test/page"])
    assert len(hits) == 1
    assert hits[0].check == "cachepoison" and hits[0].severity == "HIGH"
    assert hits[0].confidence == 0.85


def test_reflection_without_persistence_no_hit():
    def handle(url, headers):
        marker = next((v for v in headers.values() if ".invalid" in v), None)
        if marker:
            return 200, {"Cache-Control": "public, max-age=60"}, f"<html>{marker}</html>"
        return 200, {"Cache-Control": "public, max-age=60"}, "<html>clean</html>"

    c = CachePoisonChecker(session=FakeSession(handle))
    assert c.check(["https://app.test/page"]) == []


def test_non_cacheable_no_hit():
    def handle(url, headers):
        marker = next((v for v in headers.values() if ".invalid" in v), None)
        if marker:
            return 200, {"Cache-Control": "no-store"}, f"<html>{marker}</html>"
        return 200, {"Cache-Control": "no-store"}, "<html>clean</html>"

    c = CachePoisonChecker(session=FakeSession(handle))
    assert c.check(["https://app.test/page"]) == []


def test_no_reflection_no_hit():
    def handle(url, headers):
        return 200, {"Cache-Control": "public, max-age=60"}, "<html>clean</html>"

    c = CachePoisonChecker(session=FakeSession(handle))
    assert c.check(["https://app.test/page"]) == []


def test_is_cacheable_rules():
    assert _is_cacheable({"Cache-Control": "public, max-age=60"}, "") is True
    assert _is_cacheable({"Cache-Control": "no-store"}, "") is False
    assert _is_cacheable({"Cache-Control": "private"}, "") is False
    assert _is_cacheable({"X-Cache": "HIT"}, "") is True
    assert _is_cacheable({"CF-Cache-Status": "MISS"}, "") is True
    assert _is_cacheable({}, "") is False


def test_wcd_suffix_surface():
    def handle(url, headers):
        if "/x.css" in url:
            return (
                200,
                {"Content-Type": "text/html", "Cache-Control": "public, max-age=3600"},
                "<html>user</html>",
            )
        return 200, {"Content-Type": "text/html", "Cache-Control": "no-store"}, "<html>user</html>"

    c = CachePoisonChecker(session=FakeSession(handle))
    hits = c.check(["https://app.test/account"])
    assert any("Deception" in h.description or h.severity == "MEDIUM" for h in hits)


def test_cache_buster_unique_per_probe():
    seen = []

    def handle(url, headers):
        seen.append(url)
        return 200, {}, "clean"

    c = CachePoisonChecker(session=FakeSession(handle), max_headers=3)
    c.check(["https://app.test/page"])
    busters = [u.split("cb=")[-1] for u in seen if "cb=" in u]
    assert len(set(busters)) == len(busters) and len(busters) >= 3
