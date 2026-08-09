"""FullPipeline — end-to-end BlastRadius run (Phase 6).

Flow: acquire target (validate + clone) → scan → sandbox-validate →
patch/verify → disclosure reports → blast-radius graph → summary report.

Progress callbacks (``FullPipeline(progress={...})``):
    on_scan(target=..., repo_path=...)
    on_exploit(finding=...)
    on_patch(finding=...)
    on_report(finding=..., patch_result=...)
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from blastradius.blast_radius.graph import BlastRadiusGraph, parse_dependencies
from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.patcher.loop import PatchLoop, PatchResult
from blastradius.reporting.summary import SummaryReporter
from blastradius.security.input_validator import validate_github_url, validate_repo_path
from blastradius.tools.sandbox_tool import run_exploit_sandbox


@dataclass
class PipelineResult:
    """Outcome of a full pipeline run."""
    target: str
    findings: List[Finding] = field(default_factory=list)
    patches: List[Tuple[Finding, PatchResult]] = field(default_factory=list)
    reports: List[Path] = field(default_factory=list)
    blast_radius: Optional[BlastRadiusGraph] = None
    files_scanned: int = 0
    confirmed: List[Finding] = field(default_factory=list)
    dependencies: List[Tuple[str, str]] = field(default_factory=list)


class FullPipeline:
    """Orchestrate the end-to-end BlastRadius flow for one target."""

    def __init__(
        self,
        hunter: Optional[CVEHunter] = None,
        patch_loop: Optional[PatchLoop] = None,
        graph: Optional[BlastRadiusGraph] = None,
        reports_dir: str = "reports",
        progress: Optional[Dict[str, Callable]] = None,
        db: Optional[Any] = None,
        plugins: Optional[Any] = None,
    ):
        self.hunter = hunter or CVEHunter()
        self.patch_loop = patch_loop or PatchLoop()
        self.graph = graph or BlastRadiusGraph(backend="memory")
        self.reports_dir = reports_dir
        self.progress = progress or {}
        self.summary = SummaryReporter()
        # Persistent SQLite storage (created automatically; failures never break a run).
        try:
            from blastradius.db.database import SQLiteDB

            self.db = db if db is not None else SQLiteDB()
        except Exception:
            self.db = None
        # Self-improvement loop: records outcomes so rules can be learned.
        try:
            from blastradius.learning.improver import SelfImprover

            self.improver = SelfImprover()
        except Exception:
            self.improver = None
        # Plugin system: fires on_finding / on_patch / on_scan_complete.
        try:
            from blastradius.plugins.loader import PluginLoader

            self.plugins = plugins if plugins is not None else PluginLoader()
        except Exception:
            self.plugins = None
        # Tamper-evident audit log.
        try:
            from blastradius.security.audit_log import AuditLogger

            self.audit = AuditLogger()
        except Exception:
            self.audit = None

    def _audit(self, event: str, **data) -> None:
        if self.audit is None:
            return
        try:
            self.audit.log(event, **data)
        except Exception:
            pass

    def _db(self, method: str, *args, **kwargs):
        """Best-effort DB call — persistence must never break a scan."""
        if self.db is None:
            return None
        try:
            return getattr(self.db, method)(*args, **kwargs)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str) -> PipelineResult:
        """Run the full pipeline against ``target`` (GitHub URL or local path)."""
        repo_path, repo_name = self._acquire(target)
        result = PipelineResult(target=target, blast_radius=self.graph)

        self._emit("on_scan", target=target, repo_path=repo_path)
        scan_id = self._db("save_scan", target)
        self._audit("scan_started", target=target)
        findings = self.hunter.scan_repo(repo_path)
        result.findings = findings
        result.files_scanned = self.hunter.files_scanned
        self._db("update_scan", scan_id, status="running", files_scanned=result.files_scanned)

        deps = parse_dependencies(repo_path)
        result.dependencies = deps
        for name, version in deps:
            self.graph.add_package(name, version)
            self.graph.link_package_to_repo(name, repo_name)

        finding_ids: Dict[int, int] = {}
        for finding in findings:
            db_finding_id = self._db("save_finding", scan_id, finding)
            if db_finding_id is not None:
                finding_ids[finding.line] = db_finding_id
            if self.plugins is not None:
                try:
                    self.plugins.on_finding(finding)
                except Exception:
                    pass
            try:
                self._emit("on_exploit", finding=finding)
                sandbox_result = run_exploit_sandbox(
                    finding.vuln_type, reconstruct_target_code(finding)
                )
                was_fp = not sandbox_result.startswith("CONFIRMED_EXPLOITABLE")
                patch_confidence = 0.0
                if not was_fp:
                    result.confirmed.append(finding)
                    self._emit("on_patch", finding=finding)
                    patch_result = self.patch_loop.run(finding)
                    result.patches.append((finding, patch_result))
                    if self.plugins is not None:
                        try:
                            self.plugins.on_patch(patch_result)
                        except Exception:
                            pass
                    if patch_result.verification is not None:
                        patch_confidence = patch_result.verification.confidence
                        self._db("save_patch", finding_ids.get(finding.line), patch_result.patch,
                                 patch_result.attempts, patch_result.needs_human,
                                 patch_confidence)

                    self._emit("on_report", finding=finding, patch_result=patch_result)
                    report = DisclosureReport()
                    path = report.save_report(finding, repo_name, self.reports_dir, sandbox_result)
                    result.reports.append(path)
                    self._db("save_report", finding_ids.get(finding.line), str(path))
                if self.improver is not None:
                    try:
                        self.improver.record_outcome(
                            finding, was_fp=was_fp, sandbox_result=sandbox_result,
                            patch_confidence=patch_confidence,
                        )
                    except Exception:
                        pass
            except Exception:
                continue  # never let one finding break the pipeline

        self._db("update_scan", scan_id, status="done",
                 finished_at=datetime.now().isoformat(timespec="seconds"))
        # Log provider usage when the LLM was actually used for a patch.
        if any(pr.patch.source == "api" for _, pr in result.patches):
            sel = None
            try:
                from blastradius.providers.selector import auto_select

                sel = auto_select(verbose=False)
            except Exception:
                sel = None
            if sel:
                self._db("log_provider_usage", sel["provider"], sel["model"], 0, 0.0)

        summary_path = self.summary.save_summary(result, self.reports_dir)
        result.reports.append(summary_path)
        self._audit("scan_completed", target=target,
                    findings=len(result.findings), confirmed=len(result.confirmed),
                    patches=len(result.patches))
        if self.plugins is not None:
            try:
                self.plugins.on_scan_complete(result)
            except Exception:
                pass
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _acquire(self, target: str) -> Tuple[str, str]:
        """Validate and acquire the target; returns (repo_path, repo_name)."""
        if target.startswith(("http://", "https://")):
            url = validate_github_url(target)
            repo_path = self.hunter.clone_repo(url)
            repo_name = url.rstrip("/").split("/")[-1]
        else:
            repo_path = validate_repo_path(target)
            repo_name = Path(target).name or "unknown"
        return repo_path, repo_name

    def _emit(self, name: str, **data) -> None:
        callback = self.progress.get(name)
        if callback:
            callback(**data)
