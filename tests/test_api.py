"""REST API tests — DB + scans mocked, no network."""

import time

import pytest
from fastapi.testclient import TestClient

from blastradius.api import server as api_server
from blastradius.api.server import app
from blastradius.db.database import SQLiteDB
from blastradius.hunter.scanner import Finding

VULN_APP_PY = '''\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
'''


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = SQLiteDB(db_path=str(tmp_path / "api.db"))
    monkeypatch.setattr(api_server, "_db", lambda: db)
    monkeypatch.delenv("BLASTRADIUS_API_KEY", raising=False)
    return TestClient(app)


def _wait(client, job_id, timeout=15):
    for _ in range(timeout * 10):
        status = client.get(f"/api/v1/scan/{job_id}").json()
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def test_openapi_spec(client):
    spec = client.get("/api/v1/openapi.json")
    assert spec.status_code == 200
    assert spec.json()["info"]["title"] == "BlastRadius API"


def test_scan_flow(client, tmp_path, monkeypatch):
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "app.py").write_text(VULN_APP_PY, encoding="utf-8")
    monkeypatch.setattr("blastradius.hunter.scanner.CVEHunter.clone_repo",
                        lambda self, url: str(tmp_path / "repo"))

    resp = client.post("/api/v1/scan", json={"target": "https://github.com/org/demo"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert resp.json()["status"] == "queued"

    status = _wait(client, job_id)
    assert status["status"] == "done"
    # the scan job populates the in-memory store; DB-persisted /findings are
    # covered separately (test_findings_filters_and_pagination)
    assert api_server._store.findings_list()


def test_scan_requires_target(client):
    assert client.post("/api/v1/scan", json={"target": ""}).status_code == 400
    assert client.get("/api/v1/scan/nope").status_code == 404


def test_findings_filters_and_pagination(client):
    db = api_server._db()
    scan_id = db.save_scan("t")
    db.save_finding(scan_id, Finding(file="a.py", line=1, vuln_type="sqli", payload="p",
                                     confidence=0.9, severity="CRITICAL", cwe="CWE-89",
                                     description="d", remediation="r"))
    db.save_finding(scan_id, Finding(file="b.py", line=2, vuln_type="xss", payload="q",
                                     confidence=0.8, severity="HIGH", cwe="CWE-79",
                                     description="d", remediation="r"))

    by_sev = client.get("/api/v1/findings?severity=critical").json()
    assert by_sev["total"] == 1 and by_sev["findings"][0]["vuln_type"] == "sqli"

    by_type = client.get("/api/v1/findings?type=xss").json()
    assert by_type["total"] == 1

    page = client.get("/api/v1/findings?limit=1&offset=0").json()
    assert page["total"] == 2 and len(page["findings"]) == 1 and page["page"] == 1


def test_finding_detail_and_patch(client):
    db = api_server._db()
    scan_id = db.save_scan("t")
    fid = db.save_finding(scan_id, Finding(file="a.py", line=1, vuln_type="sqli",
                                           payload='query = "SELECT * FROM t WHERE id = \'" + x + "\'"',
                                           confidence=0.9, severity="CRITICAL", cwe="CWE-89",
                                           description="d", remediation="r",
                                           original_code='def target(u):\n    return "SELECT * FROM t WHERE id=\'" + u + "\'"'))

    detail = client.get(f"/api/v1/findings/{fid}").json()
    assert detail["finding"]["vuln_type"] == "sqli"
    assert "exploit_proof" in detail

    patch = client.post("/api/v1/patch", json={"finding_id": str(fid)})
    assert patch.status_code == 200
    data = patch.json()
    assert data["patch_diff"] and "needs_human" in data

    assert client.get("/api/v1/findings/999999").status_code == 404
    assert client.post("/api/v1/patch", json={}).status_code == 400


def test_stats_and_providers(client):
    stats = client.get("/api/v1/stats").json()
    assert "total_scans" in stats
    providers = client.get("/api/v1/providers").json()
    assert "active" in providers and "providers" in providers and "cost" in providers


def test_webhook_endpoint(client, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "secret")
    called = {}

    def fake_scan_and_report(repo, pr_number, clone_url, changed_files=None):
        called["repo"] = repo
        return []

    monkeypatch.setattr("blastradius.github_app.webhook.scan_and_report", fake_scan_and_report)
    body = b'{"action":"opened","pull_request":{"number":7},"repository":{"full_name":"org/r","clone_url":"https://github.com/org/r.git"}}'
    sig = "sha256=" + __import__("hmac").new(b"secret", body, __import__("hashlib").sha256).hexdigest()

    resp = client.post("/api/v1/webhook/github", content=body,
                       headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig})
    assert resp.status_code == 200
    assert resp.json()["pr"] == 7
    assert called["repo"] == "org/r"

    bad = client.post("/api/v1/webhook/github", content=body,
                      headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": "sha256=bad"})
    assert bad.status_code == 403


def test_auth_required_when_key_set(client, monkeypatch):
    monkeypatch.setenv("BLASTRADIUS_API_KEY", "sekret")
    no_auth = client.get("/api/v1/stats")
    assert no_auth.status_code == 401
    with_auth = client.get("/api/v1/stats", headers={"Authorization": "Bearer sekret"})
    assert with_auth.status_code == 200
