"""GitHub App tests — no network, no GitHub token, no Neo4j.

The webhook pipeline (scan_and_report) is monkeypatched; signature handling,
event routing, health, and comment formatting are exercised for real.
"""

import hashlib
import hmac
import json

import pytest

from blastradius.github_app.commenter import PRCommenter
from blastradius.hunter.scanner import Finding
from blastradius.patcher.generator import Patch
from blastradius.patcher.loop import PatchResult
from blastradius.patcher.verifier import VerificationResult

SECRET = "test-secret"


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def pr_payload(action="opened", repo="org/repo", pr=42):
    return {
        "action": action,
        "pull_request": {"number": pr, "base": {"ref": "main"}, "head": {"ref": "feature"}},
        "repository": {"full_name": repo, "clone_url": f"https://github.com/{repo}.git"},
    }


def push_payload():
    return {"ref": "refs/heads/main", "repository": {"full_name": "org/repo"}}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    from fastapi.testclient import TestClient

    from blastradius.github_app.webhook import app

    return TestClient(app)


def make_finding(vuln_type="sqli", confidence=0.95):
    return Finding(
        file="src/app.py",
        line=42,
        vuln_type=vuln_type,
        payload='query = "SELECT ... " + user_input',
        confidence=confidence,
        evidence="SQL error from MySQL detected in response.",
    )


def make_patch_result(needs_human=False):
    return PatchResult(
        patch=Patch(
            original_code="vuln",
            patched_code="fixed",
            explanation="parameterized query",
        ),
        verification=VerificationResult(True, True, True, 100.0),
        attempts=1,
        needs_human=needs_human,
    )


# --- Signature verification --------------------------------------------------


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": "1.0.0"}


def test_webhook_valid_signature_runs_pr_scan(client, monkeypatch):
    calls = {}

    def fake_scan(repo, pr_number, clone_url, changed_files):
        calls["repo"] = repo
        calls["pr"] = pr_number
        calls["url"] = clone_url
        return [make_finding()]

    monkeypatch.setattr("blastradius.github_app.webhook.scan_and_report", fake_scan)
    body = json.dumps(pr_payload()).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign(body)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["repo"] == "org/repo"
    assert data["pr"] == 42
    assert data["findings"] == 1
    assert calls == {"repo": "org/repo", "pr": 42, "url": "https://github.com/org/repo.git"}


def test_webhook_invalid_signature_rejected(client):
    body = json.dumps(pr_payload()).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign(body, "wrong")},
    )
    assert resp.status_code == 403


def test_webhook_missing_signature_rejected(client):
    body = json.dumps(pr_payload()).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code == 403


def test_webhook_ignores_non_pr_actions(client, monkeypatch):
    called = []

    def fake_scan(*args, **kwargs):
        called.append(args)
        return []

    monkeypatch.setattr("blastradius.github_app.webhook.scan_and_report", fake_scan)
    body = json.dumps(pr_payload(action="closed")).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "action ignored"
    assert not called


def test_webhook_push_event_acknowledged(client, monkeypatch):
    called = []

    def fake_scan(*args, **kwargs):
        called.append(args)
        return []

    monkeypatch.setattr("blastradius.github_app.webhook.scan_and_report", fake_scan)
    body = json.dumps(push_payload()).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "push event acknowledged"
    assert not called


def test_webhook_unknown_event_ignored(client):
    body = json.dumps({"repository": {"full_name": "org/repo"}}).encode()
    resp = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": sign(body)},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "event ignored"


# --- PRCommenter -------------------------------------------------------------


def test_comment_format_with_patch():
    comment = PRCommenter().build_comment(make_finding(), make_patch_result())
    assert "## 🔴 BlastRadius Security Finding" in comment
    assert "**Type:** SQLi | **Confidence:** 95% | **File:** src/app.py:42" in comment
    assert "**Status:** CONFIRMED_EXPLOITABLE → PATCH_GENERATED" in comment
    assert "<details><summary>Patch Diff</summary>" in comment
    assert "<details><summary>Exploit Proof</summary>" in comment
    assert "⚠️ Awaiting human review before merge." in comment
    assert "-patched" in comment or "+fixed" in comment  # diff rendered


def test_comment_format_patch_needs_review():
    comment = PRCommenter().build_comment(make_finding(), make_patch_result(needs_human=True))
    assert "**Status:** CONFIRMED_EXPLOITABLE → PATCH_NEEDS_REVIEW" in comment


def test_comment_format_without_patch():
    comment = PRCommenter().build_comment(make_finding(), None)
    assert "**Status:** CONFIRMED_EXPLOITABLE" in comment
    assert "(no patch available)" in comment


def test_post_comment_dry_run_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    commenter = PRCommenter(token=None)
    body = commenter.post_finding_comment("org/repo", 42, make_finding(), None)
    assert "## 🔴 BlastRadius Security Finding" in body


def test_post_comment_calls_github_api(monkeypatch):
    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return b"{}"

    def fake_urlopen(req, timeout=30):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["auth"] = req.get_header("Authorization")
        captured["body"] = json.loads(req.data) if req.data else None
        return FakeResp()

    monkeypatch.setattr(
        "blastradius.github_app.commenter.urllib.request.urlopen", fake_urlopen
    )
    commenter = PRCommenter(token="ghp_test")
    commenter.post_finding_comment("org/repo", 42, make_finding(), None)

    assert captured["url"] == "https://api.github.com/repos/org/repo/issues/42/comments"
    assert captured["method"] == "POST"
    assert captured["auth"] == "Bearer ghp_test"
    assert "BlastRadius Security Finding" in captured["body"]["body"]
