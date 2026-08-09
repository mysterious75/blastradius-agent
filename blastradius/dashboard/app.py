"""BlastRadius dashboard — FastAPI app.

Routes:
    GET /                    dashboard home (HTML)
    GET /findings            all findings JSON
    GET /findings/{id}       single finding detail
    GET /reports             list saved reports
    GET /reports/{name}      render a markdown report as HTML
    GET /blast-radius        dependency graph JSON
    GET /providers           provider status JSON
    GET /stats               summary stats JSON
    POST /scan               trigger a scan {target: str}
    GET /scan/{job_id}       scan status
    GET /ws/{job_id}         WebSocket live scan progress
"""

import html as _html
import os
import re
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from blastradius.dashboard.store import ScanStore, run_scan_job
from blastradius.providers.client import provider_key_set
from blastradius.providers.registry import PROVIDER_REGISTRY
from blastradius.providers.selector import auto_select

_HERE = Path(__file__).resolve().parent

store = ScanStore(reports_dir=os.getenv("BLASTRADIUS_REPORTS_DIR", "reports"))

app = FastAPI(title="BlastRadius Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


# ---------------------------------------------------------------------------
# Markdown -> HTML (stdlib only, minimal renderer)
# ---------------------------------------------------------------------------

def _md_to_html(md: str) -> str:
    out, in_code = [], False
    for line in md.splitlines():
        if line.startswith("```"):
            out.append("<pre>" if not in_code else "</pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(_html.escape(line))
            continue
        s = _html.escape(line)
        if s.startswith("# "):
            out.append(f"<h1>{s[2:]}</h1>")
        elif s.startswith("## "):
            out.append(f"<h2>{s[3:]}</h2>")
        elif s.startswith("### "):
            out.append(f"<h3>{s[4:]}</h3>")
        elif s.startswith("- "):
            out.append(f"<li>{s[2:]}</li>")
        elif s.startswith("> "):
            out.append(f"<blockquote>{s[2:]}</blockquote>")
        elif s.startswith("|") and "|" in s[1:]:
            out.append(f"<div class='mdrow'>{s}</div>")
        elif not s.strip():
            out.append("<br>")
        else:
            out.append(f"<p>{s}</p>")
    return "".join(out)


def _providers_status() -> list:
    selection = auto_select(verbose=False)
    active = selection["provider"] if selection else None
    rows = []
    for name, cfg in PROVIDER_REGISTRY.items():
        if cfg.get("api_key"):
            key, status = "local", "local"
        elif provider_key_set(name):
            key, status = "set", "ready"
        else:
            key, status = "none", "no key"
        rows.append({
            "provider": name,
            "model": (cfg["models"] or ["-"])[0],
            "key": key,
            "status": status,
            "active": name == active,
        })
    return rows


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home():
    index = (_HERE / "templates" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(index)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@app.get("/findings")
async def findings():
    return store.findings_list()


@app.get("/findings/{finding_id}")
async def finding_detail(finding_id: int):
    f = store.get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    f["disclosure_template"] = (
        f"## Disclosure — {f['vuln_type'].upper()} in {f['repo']}\n\n"
        f"- **File:** `{f['file']}:{f['line']}`\n"
        f"- **Severity:** {f['severity']} | **CWE:** {f['cwe']} | **Confidence:** {f['confidence']}\n"
        f"- **Payload:** `{f['payload']}`\n\n"
        f"### Exploit proof\n\n```\n{f['evidence']}\n```\n\n"
        f"### Remediation\n\n{f['remediation']}\n"
    )
    return f


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/reports")
async def reports():
    return [{"name": r["name"], "path": r["path"]} for r in store.reports_list()]


@app.get("/reports/{name}")
async def report_html(name: str):
    rep = store.get_report(name)
    if not rep:
        raise HTTPException(status_code=404, detail="report not found")
    body = _md_to_html(rep.get("content") or "")
    return HTMLResponse(
        f"<html><head><title>{_html.escape(name)}</title>"
        f"<style>body{{background:#0d1117;color:#c9d1d9;font-family:sans-serif;"
        f"padding:2rem;max-width:900px;margin:auto}}pre{{background:#161b22;"
        f"padding:1rem;border-radius:6px;overflow-x:auto}}"
        f"h1,h2,h3{{color:#ff4444}}</style></head><body>{body}</body></html>"
    )


# ---------------------------------------------------------------------------
# Blast radius / providers / stats
# ---------------------------------------------------------------------------

@app.get("/blast-radius")
async def blast_radius():
    return store.blast_radius()


@app.get("/providers")
async def providers():
    return {"active": auto_select(verbose=False), "providers": _providers_status()}


@app.get("/stats")
async def stats():
    return store.stats()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.post("/scan")
async def trigger_scan(payload: dict):
    target = (payload or {}).get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    job_id = store.start_job(target)
    threading.Thread(target=run_scan_job, args=(store, job_id, target), daemon=True).start()
    return {"job_id": job_id, "status": "pending"}


@app.get("/scan/{job_id}")
async def scan_status(job_id: str):
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"id": job["id"], "status": job["status"], "target": job["target"],
            "files_scanned": job["files_scanned"], "messages": job["messages"]}


@app.websocket("/ws/{job_id}")
async def ws_progress(job_id: str, websocket: WebSocket):
    await websocket.accept()
    sent = 0
    try:
        while True:
            job = store.get_job(job_id)
            if not job:
                await websocket.send_json({"type": "status", "status": "unknown"})
                break
            messages = job.get("messages", [])
            while sent < len(messages):
                await websocket.send_json({"type": "progress", "message": messages[sent]})
                sent += 1
            if job["status"] in ("done", "failed"):
                await websocket.send_json({"type": "status", "status": job["status"]})
                break
            import asyncio

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
