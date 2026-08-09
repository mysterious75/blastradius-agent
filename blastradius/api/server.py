"""BlastRadius REST API — JSON only, Bearer auth, separate from the dashboard.

Auth: when BLASTRADIUS_API_KEY is set, every /api/v1 route requires
`Authorization: Bearer <key>`. Without it the API runs in dev mode (no auth)
and warns on startup.
"""

import json
import os
import sys
import threading
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from blastradius.dashboard.store import ScanStore, run_scan_job

app = FastAPI(title="BlastRadius API", version="1.0.0")
_bearer = HTTPBearer(auto_error=False)
_store = ScanStore()

_API_KEY = os.getenv("BLASTRADIUS_API_KEY", "")
if not _API_KEY:
    print("WARNING: BLASTRADIUS_API_KEY not set — API running in dev mode without auth.",
          file=sys.stderr)


def _require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)):
    api_key = os.getenv("BLASTRADIUS_API_KEY", "")  # read lazily (env can change at runtime)
    if not api_key:
        return  # dev mode
    if credentials is None or credentials.credentials != api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def _db():
    from blastradius.db.database import SQLiteDB

    return SQLiteDB()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@app.post("/api/v1/scan", dependencies=[Depends(_require_auth)])
async def create_scan(payload: dict):
    target = (payload or {}).get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    job_id = _store.start_job(target)
    threading.Thread(target=run_scan_job, args=(_store, job_id, target), daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/v1/scan/{job_id}", dependencies=[Depends(_require_auth)])
async def scan_status(job_id: str):
    job = _store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "status": job["status"],
        "progress": round(len(job.get("messages", [])) * 10),
        "findings_count": len([f for f in _store.findings_list() if f["scan_id"] == job_id]),
        "eta": None,
    }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@app.get("/api/v1/findings", dependencies=[Depends(_require_auth)])
async def list_findings(severity: str = "", type: str = "", limit: int = 50, offset: int = 0):
    rows = _db().get_all_findings()
    if severity:
        rows = [r for r in rows if str(r.get("severity", "")).lower() == severity.lower()]
    if type:
        rows = [r for r in rows if str(r.get("vuln_type", "")).lower() == type.lower()]
    limit = max(1, min(limit, 500))
    total = len(rows)
    page = rows[offset:offset + limit]
    return {"findings": page, "total": total, "page": offset // limit + 1}


@app.get("/api/v1/findings/{finding_id}", dependencies=[Depends(_require_auth)])
async def finding_detail(finding_id: int):
    db = _db()
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")
    finding = dict(row)
    patch = db.get_patch(finding_id)
    return {
        "finding": finding,
        "patch": dict(patch) if patch else None,
        "exploit_proof": finding.get("evidence", ""),
    }


@app.post("/api/v1/patch", dependencies=[Depends(_require_auth)])
async def create_patch(payload: dict):
    from blastradius.hunter.scanner import Finding
    from blastradius.patcher.loop import PatchLoop

    finding_id = (payload or {}).get("finding_id")
    if finding_id is None:
        raise HTTPException(status_code=400, detail="finding_id is required")
    db = _db()
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (int(finding_id),)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")

    finding = Finding(
        file=row["file"], line=row["line"], vuln_type=row["vuln_type"],
        payload=row["payload"], confidence=row["confidence"], severity=row["severity"],
        cwe=row["cwe"], description=row["description"], remediation=row["remediation"],
        original_code=row["payload"],
    )
    result = PatchLoop().run(finding)
    confidence = result.verification.confidence if result.verification else 0.0
    db.save_patch(finding_id, result.patch, result.attempts, result.needs_human, confidence)
    return {
        "patch_diff": result.patch.diff,
        "confidence": confidence,
        "needs_human": result.needs_human,
    }


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


@app.get("/api/v1/stats", dependencies=[Depends(_require_auth)])
async def stats():
    return _db().get_stats()


@app.get("/api/v1/providers", dependencies=[Depends(_require_auth)])
async def providers():
    from blastradius.providers.client import provider_key_set
    from blastradius.providers.cost_tracker import cost_tracker
    from blastradius.providers.registry import PROVIDER_REGISTRY
    from blastradius.providers.selector import auto_select

    sel = auto_select(verbose=False)
    rows = [
        {"provider": name, "key_set": provider_key_set(name),
         "model": (cfg["models"] or ["-"])[0]}
        for name, cfg in PROVIDER_REGISTRY.items()
    ]
    return {"active": sel, "providers": rows, "cost": cost_tracker.get_session_cost()}


@app.post("/api/v1/webhook/github")
async def github_webhook(request: Request,
                         x_hub_signature_256: Optional[str] = Header(default=None)):
    from blastradius.github_app.webhook import get_webhook_secret, scan_and_report, verify_signature

    body = await request.body()
    if not verify_signature(get_webhook_secret(), body, x_hub_signature_256 or ""):
        raise HTTPException(status_code=403, detail="invalid signature")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}")

    event = request.headers.get("x-github-event")
    if event == "pull_request" and payload.get("action") in ("opened", "synchronize"):
        repo = payload["repository"]["full_name"]
        pr_number = payload["pull_request"]["number"]
        clone_url = payload["repository"]["clone_url"]
        findings = scan_and_report(repo, pr_number, clone_url)
        return {"status": "ok", "repo": repo, "pr": pr_number, "findings": len(findings)}
    return {"status": "ok", "event": event, "message": "ignored"}


@app.get("/api/v1/openapi.json")
async def openapi_spec():
    return app.openapi()
