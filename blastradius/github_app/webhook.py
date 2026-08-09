"""BlastRadius GitHub App webhook (FastAPI).

- POST /webhook — verifies X-Hub-Signature-256 (HMAC-SHA256 with
  GITHUB_WEBHOOK_SECRET), handles pull_request (opened/synchronize) and push
  events. On a PR it scans the repo, sandbox-validates findings, generates
  patches, and posts PR comments.
- GET /health — liveness probe.
"""

import hashlib
import hmac
import json
import os
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, Request

from blastradius.github_app.commenter import PRCommenter
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.patcher.loop import PatchLoop, PatchResult
from blastradius.tools.sandbox_tool import run_exploit_sandbox

VERSION = "1.0.0"

app = FastAPI(title="BlastRadius GitHub App", version=VERSION)

PR_ACTIONS = ("opened", "synchronize")


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """Verify the X-Hub-Signature-256 header against the raw request body."""
    if not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def get_webhook_secret() -> str:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        raise RuntimeError("GITHUB_WEBHOOK_SECRET is not set")
    return secret


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def changed_files_from_payload(payload: dict) -> Optional[List[str]]:
    """Best-effort changed-file list from the webhook payload.

    GitHub's pull_request payload does not include the file list; this returns
    None unless the payload was enriched with one (e.g. by an API call).
    """
    files = payload.get("_changed_files")
    return files if isinstance(files, list) else None


def scan_and_report(
    repo: str,
    pr_number: int,
    clone_url: str,
    changed_files: Optional[List[str]] = None,
    hunter: Optional[CVEHunter] = None,
    commenter: Optional[PRCommenter] = None,
) -> List[Finding]:
    """Clone, scan, sandbox-validate, patch, and comment on a PR.

    Returns the findings that were processed. Network-dependent pieces
    (clone, comment post) degrade gracefully when tokens/network are absent.
    """
    hunter = hunter or CVEHunter()
    commenter = commenter or PRCommenter()
    patch_loop = PatchLoop()

    repo_path = hunter.clone_repo(clone_url)
    findings = hunter.scan_repo(repo_path)
    if changed_files:
        findings = [
            f for f in findings
            if any(changed in f.file for changed in changed_files)
        ]

    for finding in findings:
        try:
            sandbox_result = run_exploit_sandbox(
                finding.vuln_type, reconstruct_target_code(finding)
            )
            if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
                continue
            patch_result: PatchResult = patch_loop.run(finding)
            commenter.post_finding_comment(
                repo, pr_number, finding, patch_result, sandbox_result
            )
        except Exception:
            continue  # never let one finding break the webhook
    return findings


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "ok", "version": VERSION}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
):
    body = await request.body()
    if not verify_signature(get_webhook_secret(), body, x_hub_signature_256 or ""):
        raise HTTPException(status_code=403, detail="invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON payload: {exc}")

    if x_github_event == "pull_request":
        if payload.get("action") in PR_ACTIONS:
            repo = payload["repository"]["full_name"]
            pr_number = payload["pull_request"]["number"]
            clone_url = payload["repository"]["clone_url"]
            changed = changed_files_from_payload(payload)
            findings = scan_and_report(repo, pr_number, clone_url, changed)
            return {
                "status": "ok",
                "event": "pull_request",
                "repo": repo,
                "pr": pr_number,
                "findings": len(findings),
            }
        return {"status": "ok", "event": "pull_request", "message": "action ignored"}

    if x_github_event == "push":
        return {"status": "ok", "event": "push", "message": "push event acknowledged"}

    return {"status": "ok", "event": x_github_event, "message": "event ignored"}


def start(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the webhook server (console script entry point: blastradius-server)."""
    import uvicorn

    reload = os.getenv("BLASTRADIUS_RELOAD", "").lower() in ("1", "true", "yes")
    uvicorn.run("blastradius.github_app.webhook:app", host=host, port=port, reload=reload)
