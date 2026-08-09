"""In-memory scan store for the dashboard.

Thread-safe; holds scan jobs, findings, reports and aggregates stats. The
SQLiteDB (blastradius/db) persists the same data long-term; this store keeps
the dashboard responsive without a database dependency.
"""

import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from blastradius.blast_radius.graph import BlastRadiusGraph, parse_dependencies
from blastradius.hunter.scanner import CVEHunter, Finding
from blastradius.security.input_validator import validate_github_url, validate_repo_path


class ScanStore:
    """Thread-safe in-memory store for dashboard state."""

    def __init__(self, reports_dir: str = "reports"):
        self._lock = threading.Lock()
        self.jobs: Dict[str, dict] = {}
        self.findings: Dict[int, dict] = {}
        self._finding_seq = 0
        self.reports: List[dict] = []
        self.reports_dir = reports_dir
        self.graph = BlastRadiusGraph(backend="memory")
        self.patches_generated = 0
        self.confirmed_cves = 0
        self.repos_monitored: set = set()

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def start_job(self, target: str) -> str:
        job_id = f"scan-{int(time.time() * 1000)}-{len(self.jobs)}"
        with self._lock:
            self.jobs[job_id] = {
                "id": job_id,
                "target": target,
                "status": "pending",
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "finished_at": None,
                "files_scanned": 0,
                "messages": [],
            }
        return job_id

    def update_job(self, job_id: str, **kw) -> None:
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(kw)

    def get_job(self, job_id: str) -> Optional[dict]:
        with self._lock:
            job = self.jobs.get(job_id)
            return dict(job) if job else None

    def add_message(self, job_id: str, message: str) -> None:
        with self._lock:
            if job_id in self.jobs:
                self.jobs[job_id]["messages"].append(message)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, job_id: str, finding: Finding, repo: str) -> int:
        with self._lock:
            self._finding_seq += 1
            fid = self._finding_seq
            self.findings[fid] = {
                "id": fid,
                "scan_id": job_id,
                "repo": repo,
                "file": finding.file,
                "line": finding.line,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "payload": finding.payload,
                "evidence": finding.evidence,
                "description": finding.description,
                "remediation": finding.remediation,
                "cwe": finding.cwe,
            }
            return fid

    def findings_list(self) -> List[dict]:
        with self._lock:
            return sorted(self.findings.values(), key=lambda f: f["id"], reverse=True)

    def get_finding(self, finding_id: int) -> Optional[dict]:
        with self._lock:
            return self.findings.get(finding_id)

    def mark_confirmed(self, finding_id: int) -> None:
        with self._lock:
            self.confirmed_cves += 1

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def add_report(self, name: str, path: str, content: str = "") -> None:
        with self._lock:
            self.reports.append({"name": name, "path": path, "content": content})

    def reports_list(self) -> List[dict]:
        found = {}
        for rep in self.reports:
            found[rep["name"]] = rep
        try:
            from pathlib import Path

            base = Path(self.reports_dir)
            if base.is_dir():
                for p in sorted(base.glob("*.md")):
                    found.setdefault(p.name, {"name": p.name, "path": str(p), "content": ""})
        except Exception:
            pass
        return sorted(found.values(), key=lambda r: r["name"])

    def get_report(self, name: str) -> Optional[dict]:
        for rep in self.reports_list():
            if rep["name"] == name:
                if not rep.get("content") and rep.get("path"):
                    try:
                        rep["content"] = open(rep["path"], encoding="utf-8").read()
                    except Exception:
                        pass
                return rep
        return None

    # ------------------------------------------------------------------
    # Stats + misc
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            jobs = list(self.jobs.values())
            done = [j for j in jobs if j["status"] == "done"]
            return {
                "total_scans": len(done),
                "confirmed_cves": self.confirmed_cves,
                "patches_generated": self.patches_generated,
                "repos_monitored": len(self.repos_monitored),
                "findings": len(self.findings),
                "success_rate": round(len(done) / len(jobs) * 100, 1) if jobs else 0.0,
            }

    def blast_radius(self) -> dict:
        with self._lock:
            nodes = [
                {"id": name, "type": "package"} for name in self.graph.backend.packages
            ]
            nodes += [
                {"id": name, "type": "repo"} for name in self.graph.backend.repos
            ]
            links = [
                {"source": pkg, "target": repo}
                for pkg, repos in self.graph.backend.links.items()
                for repo in repos
            ]
            return {"nodes": nodes, "links": links}


def run_scan_job(store: ScanStore, job_id: str, target: str) -> None:
    """Background scan executor (runs in a thread)."""
    store.update_job(job_id, status="running",
                     started_at=datetime.now().isoformat(timespec="seconds"))
    hunter = CVEHunter()
    try:
        if target.startswith(("http://", "https://")):
            url = validate_github_url(target)
            store.add_message(job_id, f"Cloning {url}")
            repo_path = hunter.clone_repo(url)
            repo_name = url.rstrip("/").split("/")[-1]
        else:
            repo_path = validate_repo_path(target)
            repo_name = target.rstrip("/\\").split("/")[-1].split("\\")[-1]
        store.add_message(job_id, "Scanning repository…")
        findings = hunter.scan_repo(repo_path)
        store.update_job(job_id, files_scanned=hunter.files_scanned)
        with store._lock:
            store.repos_monitored.add(repo_name)
        for finding in findings:
            store.add_finding(job_id, finding, repo_name)
        store.add_message(job_id, f"Found {len(findings)} candidate finding(s).")

        try:
            for name, version in parse_dependencies(repo_path):
                store.graph.add_package(name, version)
                store.graph.link_package_to_repo(name, repo_name)
        except Exception:
            pass

        store.update_job(job_id, status="done",
                         finished_at=datetime.now().isoformat(timespec="seconds"))
        store.add_message(job_id, "Scan complete.")
    except Exception as exc:
        store.add_message(job_id, f"ERROR: {exc}")
        store.update_job(job_id, status="failed",
                         finished_at=datetime.now().isoformat(timespec="seconds"))
