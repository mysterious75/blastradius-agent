"""Offline tests for live SQLi + mass-assignment checks (fake sessions, no network)."""

from blastradius.payloads import (
    massassign_fields,
    nosqli_payloads,
    sqli_payloads,
    sqli_time_payloads,
)
from blastradius.web.browser import Page
from blastradius.web.massassign import MassassignChecker
from blastradius.web.sqli import SqliChecker


class FakeSession:
    """URL -> (status, body, delay_s). Records calls."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def _key(self, url, params):
        if params:
            q = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
            return f"{url}?{q}"
        return url

    def get(self, url, params=None):
        import time

        key = self._key(url, params)
        self.calls.append(key)
        for pattern, (status, body, delay) in self.routes.items():
            if pattern in key:
                time.sleep(delay)
                return Page(url=key, status=status, headers={}, text=body)
        return Page(url=key, status=200, headers={}, text="ok")

    def _request(self, method, url, data=None, headers=None):
        import json as _json

        self.calls.append((method, url, data))
        for pattern, (status, body, delay) in self.routes.items():
            if pattern in url or (data and pattern in data.decode()):
                return Page(url=url, status=status, headers={}, text=body)
        if method == "POST" and data:
            try:
                echoed = _json.dumps(_json.loads(data.decode()))
            except Exception:  # noqa: BLE001 - fake must not crash on bad input
                echoed = ""
            return Page(url=url, status=200, headers={}, text=echoed)
        return Page(url=url, status=200, headers={}, text="ok")


# --- payload catalog sanity ----------------------------------------------


def test_payload_catalogs_nonempty():
    assert len(sqli_payloads()) >= 5
    assert len(sqli_time_payloads()) >= 2
    assert len(nosqli_payloads()) >= 3
    assert "is_admin" in massassign_fields()


# --- SQLi error-based -------------------------------------------------------


def test_detects_error_based_sqli():
    routes = {"'": (200, "You have an error in your SQL syntax near ''1'''", 0)}
    c = SqliChecker(session=FakeSession(routes))
    hits = c.check(["https://app.test/search?q=x"])
    assert len(hits) == 1
    assert hits[0].check == "sqli-error" and hits[0].cwe == "CWE-89"


def test_clean_param_no_hit():
    c = SqliChecker(session=FakeSession({}))
    assert c.check(["https://app.test/search?q=x"]) == []


def test_no_query_string_no_hit():
    c = SqliChecker(session=FakeSession({}))
    assert c.check(["https://app.test/about"]) == []


# --- SQLi boolean differential ----------------------------------------------


def test_detects_boolean_differential():
    def routes_fn():
        return {
            "1%3D1": (200, "AAAADMIN-LIST-TRUE", 0),
            "1%3D2": (200, "nothing", 0),
        }

    # FakeSession matches on substring; craft distinct bodies per payload.
    class BoolSession(FakeSession):
        def get(self, url, params=None):
            key = self._key(url, params)
            self.calls.append(key)
            if "1%3D1" in key or "1=1" in key:
                return Page(url=key, status=200, headers={}, text="RESULT-TRUE-X")
            return Page(url=key, status=200, headers={}, text="")

    c = SqliChecker(session=BoolSession({}))
    hits = c.check(["https://app.test/items?id=1"])
    assert len(hits) == 1 and hits[0].check == "sqli-boolean"


def test_unstable_differential_no_hit():
    class FlipSession(FakeSession):
        def __init__(self):
            super().__init__({})
            self.n = 0

        def get(self, url, params=None):
            self.n += 1
            return Page(url=url, status=200, headers={}, text=f"body-{self.n}")

    c = SqliChecker(session=FlipSession())
    assert c.check(["https://app.test/items?id=1"]) == []


# --- SQLi time-based (opt-in) -------------------------------------------------


def test_time_based_opt_in_detects_sleep():
    routes = {"SLEEP": (200, "ok", 5.0)}
    c = SqliChecker(session=FakeSession(routes), enable_time_based=True, time_threshold_s=4.0)
    hits = c.check(["https://app.test/items?id=1"])
    assert any(h.check == "sqli-time" for h in hits)


def test_time_based_off_by_default():
    routes = {"SLEEP": (200, "ok", 5.0)}
    c = SqliChecker(session=FakeSession(routes))
    assert all(h.check != "sqli-time" for h in c.check(["https://app.test/items?id=1"]))


# --- NoSQL --------------------------------------------------------------------


def test_nosql_operator_accepted():
    routes = {"$gt": (200, '{"ok":true,"user":"admin"}', 0)}
    c = SqliChecker(session=FakeSession(routes))
    hits = c.probe_nosql_body("https://app.test/api/login", {"username": "a"})
    assert len(hits) == 1 and hits[0].check == "nosqli"


# --- mass assignment ------------------------------------------------------------


def test_massassign_reflected_medium():
    s = FakeSession({})
    c = MassassignChecker(session=s)
    hits = c.check("https://app.test/api/profile", {"name": "bob"})
    assert hits, "echoing endpoint should reflect sentinel"
    assert all(h.check == "massassign" for h in hits)
    assert all(h.severity == "MEDIUM" for h in hits)


def test_massassign_persisted_high():
    class PersistSession(FakeSession):
        def _request(self, method, url, data=None, headers=None):
            if method == "GET":
                return Page(url=url, status=200, headers={}, text='{"role":"blastradius-probe"}')
            return super()._request(method, url, data, headers)

    c = MassassignChecker(session=PersistSession(), verify_url="https://app.test/api/me")
    hits = c.check("https://app.test/api/profile", {"name": "bob"})
    assert any(h.severity == "HIGH" for h in hits)


def test_massassign_ignored_field_no_hit():
    class StrictSession(FakeSession):
        def _request(self, method, url, data=None, headers=None):
            return Page(url=url, status=200, headers={}, text='{"name":"bob"}')

    c = MassassignChecker(session=StrictSession())
    assert c.check("https://app.test/api/profile", {"name": "bob"}) == []


def test_massassign_400_no_hit():
    class DenySession(FakeSession):
        def _request(self, method, url, data=None, headers=None):
            return Page(url=url, status=400, headers={}, text="bad")

    c = MassassignChecker(session=DenySession())
    assert c.check("https://app.test/api/profile", {"name": "bob"}) == []
