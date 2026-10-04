"""GraphqlChecker tests — fake sessions, no network."""

import json

from blastradius.web.graphql import (
    GraphqlChecker,
    describe_resolver_risks,
)


class Page:
    def __init__(self, text, status=200):
        self.text = text
        self.status = status
        self.headers = {}


class FakeSession:
    """Canned GraphQL endpoint keyed by query substring."""

    VULNERABLE = True

    def _request(self, method, url, data=None, headers=None):
        query = json.loads(data.decode()).get("query", "")
        if "__schema" in query:
            if self.VULNERABLE:
                return Page(json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}))
            return Page(json.dumps({"errors": [{"message": "introspection disabled"}]}))
        if "blast_radius_nonexistent_field_xyz" in query:
            if self.VULNERABLE:
                return Page(
                    json.dumps(
                        {
                            "errors": [
                                {
                                    "message": 'Cannot query field "blast_radius_nonexistent_field_xyz" '
                                    'on type "Query". Did you mean "user"?'
                                }
                            ]
                        }
                    )
                )
            return Page(json.dumps({"errors": [{"message": "field not found"}]}))
        if "blast_alias_" in query:
            count = query.count("blast_alias_")
            if self.VULNERABLE:
                return Page(
                    json.dumps({"data": {f"blast_alias_{i}": "Query" for i in range(count)}})
                )
            return Page(json.dumps({"errors": [{"message": "too many operations"}]}))
        if "__typename" in query:
            return Page(json.dumps({"data": {"__typename": "Query"}}))
        return Page("not found", status=404)


class HardenedSession(FakeSession):
    VULNERABLE = False


def checks(findings):
    return {f.check for f in findings}


# ------------------------------------------------------------- discovery


def test_discovers_endpoint_and_reports_all_three():
    findings = GraphqlChecker(session=FakeSession()).check("http://lab.invalid")
    assert checks(findings) == {
        "graphql-introspection",
        "graphql-suggestions",
        "graphql-batching",
    }
    assert all(f.url.endswith("/graphql") for f in findings)


def test_no_endpoint_no_findings():
    class Dead:
        def _request(self, *args, **kwargs):
            raise ConnectionError("down")

    assert GraphqlChecker(session=Dead()).check("http://lab.invalid") == []


def test_non_graphql_json_not_mistaken():
    class JsonApi:
        def _request(self, *args, **kwargs):
            return Page(json.dumps({"users": [{"id": 1}]}))

    assert GraphqlChecker(session=JsonApi()).check("http://lab.invalid") == []


# ------------------------------------------------------------- negatives


def test_hardened_endpoint_clean():
    assert GraphqlChecker(session=HardenedSession()).check("http://lab.invalid") == []


def test_introspection_disabled_no_finding():
    class NoIntro(FakeSession):
        VULNERABLE = True

        def _request(self, method, url, data=None, headers=None):
            query = json.loads(data.decode()).get("query", "")
            if "__schema" in query:
                return Page(json.dumps({"errors": [{"message": "introspection disabled"}]}))
            return super()._request(method, url, data=data, headers=headers)

    findings = GraphqlChecker(session=NoIntro()).check("http://lab.invalid")
    assert "graphql-introspection" not in checks(findings)
    assert "graphql-suggestions" in checks(findings)


def test_batch_capped_no_finding():
    class Capped(FakeSession):
        def _request(self, method, url, data=None, headers=None):
            query = json.loads(data.decode()).get("query", "")
            if "blast_alias_" in query:
                return Page(
                    json.dumps({"data": {"blast_alias_0": "Query"}})
                )  # only 1 of 10 executed
            return super()._request(method, url, data=data, headers=headers)

    findings = GraphqlChecker(session=Capped()).check("http://lab.invalid")
    assert "graphql-batching" not in checks(findings)


# ------------------------------------------------------------- metadata


def test_findings_carry_reporting_metadata():
    findings = GraphqlChecker(session=FakeSession()).check("http://lab.invalid")
    assert findings, "expected findings from the vulnerable fake"
    for finding in findings:
        assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert finding.cwe.startswith("CWE-")
        assert finding.description and finding.remediation
        assert 0 < finding.confidence <= 1


def test_describe_resolver_risks_flags_sensitive_names():
    notes = describe_resolver_risks(
        {"Query": ["user", "health"], "Mutation": ["updateUserRole", "ping"]}
    )
    assert any("updateUserRole" in n for n in notes)
    assert not any("health" in n or "ping" in n for n in notes)


def test_describe_resolver_risks_empty_schema():
    assert describe_resolver_risks({}) == []
