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
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

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
    ):
        self.hunter = hunter or CVEHunter()
        self.patch_loop = patch_loop or PatchLoop()
        self.graph = graph or BlastRadiusGraph(backend="memory")
        self.reports_dir = reports_dir
        self.progress = progress or {}
        self.summary = SummaryReporter()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str) -> PipelineResult:
        """Run the full pipeline against ``target`` (GitHub URL or local path)."""
        repo_path, repo_name = self._acquire(target)
        result = PipelineResult(target=target, blast_radius=self.graph)

        self._emit("on_scan", target=target, repo_path=repo_path)
        findings = self.hunter.scan_repo(repo_path)
        result.findings = findings
        result.files_scanned = self.hunter.files_scanned

        deps = parse_dependencies(repo_path)
        result.dependencies = deps
        for name, version in deps:
            self.graph.add_package(name, version)
            self.graph.link_package_to_repo(name, repo_name)

        for finding in findings:
            try:
                self._emit("on_exploit", finding=finding)
                sandbox_result = run_exploit_sandbox(
                    finding.vuln_type, reconstruct_target_code(finding)
                )
                if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
                    continue

                result.confirmed.append(finding)
                self._emit("on_patch", finding=finding)
                patch_result = self.patch_loop.run(finding)
                result.patches.append((finding, patch_result))

                self._emit("on_report", finding=finding, patch_result=patch_result)
                report = DisclosureReport()
                path = report.save_report(finding, repo_name, self.reports_dir, sandbox_result)
                result.reports.append(path)
            except Exception:
                continue  # never let one finding break the pipeline

        summary_path = self.summary.save_summary(result, self.reports_dir)
        result.reports.append(summary_path)
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
