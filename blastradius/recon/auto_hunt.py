"""AutoHunt — autonomous CVE hunt over discovered targets.

Discover targets via DorkEngine, clone + scan each (parallel, bounded
workers), apply the quick 3-check FP filter, sandbox-validate survivors, save
reports for confirmed findings, and print the summary table.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, Finding, reconstruct_target_code
from blastradius.recon.dorker import DorkEngine
from blastradius.tools.sandbox_tool import run_exploit_sandbox

# Vendored/noise path parts excluded from findings before sandbox validation
FP_PATH_PARTS = {
    "node_modules",
    "vendor",
    "dist",
    "libs",
    "assets",
    "tests",
    "docs",
    "examples",
    "migrations",
    "__pycache__",
    "static",
    "public",
}

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _fp_filter(findings: List[Finding]) -> List[Finding]:
    """Quick filter: drop vendored/tests/docs/minified candidates."""
    survivors = []
    for f in findings:
        parts = Path(f.file).parts
        if any(p in FP_PATH_PARTS for p in parts):
            continue
        if "min." in Path(f.file).name:
            continue
        survivors.append(f)
    return survivors


class AutoHunt:
    """Orchestrate discovery -> scan -> filter -> sandbox -> report."""

    def __init__(
        self,
        dork_engine: Optional[DorkEngine] = None,
        hunter: Optional[CVEHunter] = None,
        reports_dir: str = "reports/auto_hunt",
        workers: int = 3,
    ):
        self.dork = dork_engine or DorkEngine()
        self.hunter = hunter or CVEHunter()
        self.reports_dir = reports_dir
        self.workers = workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self, strategy: str = "github", max_targets: int = 20, min_stars: int = 100
    ) -> List[Dict]:
        """Hunt over up to ``max_targets`` discovered targets; returns result rows."""
        targets = self.dork.find_targets(strategy, min_stars=min_stars)[:max_targets]

        results: List[Dict] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._hunt_one, t): t for t in targets}
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda r: r.get("confirmed", 0), reverse=True)
        self._print_table(results)
        return results

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _hunt_one(self, target: Dict) -> Dict:
        repo_url = target.get("url", "")
        base = {
            "repo": target.get("repo") or repo_url,
            "stars": target.get("stars", 0),
            "files": 0,
            "confirmed": 0,
            "severity": "-",
            "report": "-",
        }
        if not repo_url or "github.com" not in repo_url:
            return base
        try:
            repo_path = self.hunter.clone_repo(repo_url)
            survivors = _fp_filter(self.hunter.scan_repo(repo_path))
            confirmed = []
            for finding in survivors:
                sandbox_result = run_exploit_sandbox(
                    finding.vuln_type, reconstruct_target_code(finding)
                )
                if not sandbox_result.startswith("CONFIRMED_EXPLOITABLE"):
                    continue
                repo_name = repo_url.rstrip("/").split("/")[-1]
                report = DisclosureReport().save_report(
                    finding, repo_name, self.reports_dir, sandbox_result
                )
                confirmed.append((finding, report))

            severity = "-"
            if confirmed:
                severity = max(
                    (f.severity for f, _ in confirmed),
                    key=lambda s: _SEVERITY_RANK.get(s, 0),
                )
            return {
                **base,
                "files": self.hunter.files_scanned,
                "confirmed": len(confirmed),
                "severity": severity,
                "report": confirmed[0][1] if confirmed else "-",
            }
        except Exception as exc:
            return {**base, "severity": "ERR", "report": str(exc)[:80]}

    @staticmethod
    def _print_table(results: List[Dict]) -> None:
        header = f"{'Repo':<32} {'Stars':>6} {'Files':>6} {'Confirmed':>10} {'Severity':>9}  Report"
        print(header)
        print("-" * len(header))
        for r in results:
            print(
                f"{str(r['repo'])[:31]:<32} {r['stars']:>6} {r['files']:>6} "
                f"{r['confirmed']:>10} {str(r['severity'])[:8]:>9}  {r['report']}"
            )
