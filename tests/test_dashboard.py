"""Dashboard tests — mocked scans, no network."""

import time

import pytest
from fastapi.testclient import TestClient

from blastradius.dashboard.app import app
from blastradius.dashboard.store import ScanStore

VULN_APP_PY = '''\
from flask import request

def search():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
'''


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def vuln_repo(tmp_path):
    (tmp_path / "app.py").write_text(VULN_APP_PY)
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\n")
    return tmp_path


def _wait_done(client, job_id, timeout=15):
    for _ in range(timeout * 10):
        status = client.get(f"/scan/{job_id}").json()
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.1)
    raise AssertionError("scan did not finish in time")


def test_home_serves_dashboard(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "BlastRadius Agent" in resp.text
    assert "New Scan" in resp.text
    assert "d3" in resp.text  # D3 via CDN for the graph tab


def test_stats_and_providers_endpoints(client):
    stats = client.get("/stats").json()
    assert set(stats) == {"total_scans", "confirmed_cves", "patches_generated",
                          "repos_monitored", "findings", "success_rate"}
    providers = client.get("/providers").json()
    assert "active" in providers and "providers" in providers
    names = {p["provider"] for p in providers["providers"]}
    assert "opencode_zen" in names and "ollama" in names


def test_findings_flow(client, vuln_repo, monkeypatch):
    monkeypatch.setattr("blastradius.hunter.scanner.CVEHunter.clone_repo",
                        lambda self, url: str(vuln_repo))
    resp = client.post("/scan", json={"target": "https://github.com/org/demo"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    done = _wait_done(client, job_id)
    assert done["status"] == "done"
    assert done["files_scanned"] >= 1

    findings = client.get("/findings").json()
    assert findings and any(f["vuln_type"] == "sqli" for f in findings)
    f = findings[0]
    detail = client.get(f"/findings/{f['id']}").json()
    assert detail["id"] == f["id"]
    assert "disclosure_template" in detail
    assert "Exploit proof" in detail["disclosure_template"]

    stats = client.get("/stats").json()
    assert stats["total_scans"] >= 1
    assert stats["repos_monitored"] >= 1


def test_scan_requires_target(client):
    resp = client.post("/scan", json={"target": "  "})
    assert resp.status_code == 400


def test_scan_not_found(client):
    assert client.get("/scan/nope").status_code == 404


def test_finding_not_found(client):
    assert client.get("/findings/999999").status_code == 404


def test_reports_endpoint(client, tmp_path):
    (tmp_path / "2026-08-09_sqli_demo.md").write_text(
        "# Vulnerability Disclosure\n\n## PoC\n\n```\npayload\n```\n", encoding="utf-8"
    )
    from blastradius.dashboard.app import store

    store.reports_dir = str(tmp_path)
    names = [r["name"] for r in client.get("/reports").json()]
    assert "2026-08-09_sqli_demo.md" in names

    html = client.get("/reports/2026-08-09_sqli_demo.md")
    assert html.status_code == 200
    assert "<h1>Vulnerability Disclosure</h1>" in html.text
    assert "payload" in html.text
    assert client.get("/reports/missing.md").status_code == 404


def test_blast_radius_graph(client, vuln_repo, monkeypatch):
    monkeypatch.setattr("blastradius.hunter.scanner.CVEHunter.clone_repo",
                        lambda self, url: str(vuln_repo))
    client.post("/scan", json={"target": "https://github.com/org/demo"})
    _wait_done(client, client.post("/scan", json={"target": "https://github.com/org/demo2"}).json()["job_id"])
    graph = client.get("/blast-radius").json()
    assert "nodes" in graph and "links" in graph
    types = {n["type"] for n in graph["nodes"]}
    assert "package" in types and "repo" in types


def test_websocket_progress(client, vuln_repo, monkeypatch):
    monkeypatch.setattr("blastradius.hunter.scanner.CVEHunter.clone_repo",
                        lambda self, url: str(vuln_repo))
    job_id = client.post("/scan", json={"target": "https://github.com/org/wsdemo"}).json()["job_id"]
    _wait_done(client, job_id)
    with client.websocket_connect(f"/ws/{job_id}") as ws:
        got = []
        while True:
            msg = ws.receive_json()
            got.append(msg)
            if msg.get("type") == "status":
                break
    assert any(m["type"] == "progress" for m in got)
    assert got[-1]["status"] == "done"
