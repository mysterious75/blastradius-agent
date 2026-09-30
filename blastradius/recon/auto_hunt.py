"""AutoHunt — autonomous CVE hunt over discovered targets.

Discover targets via DorkEngine, clone + scan each (parallel, bounded
workers), apply the quick 3-check FP filter, sandbox-validate survivors, save
reports for confirmed findings, and print the summary table.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from typing import Dict, List, Optional

from blastradius.filters import FP_PATH_PARTS, fp_filter
from blastradius.hunter.disclosure import DisclosureReport
from blastradius.hunter.scanner import CVEHunter, reconstruct_target_code
from blastradius.recon.dorker import DorkEngine
from blastradius.tools.sandbox_tool import run_exploit_sandbox

__all__ = ["AutoHunt", "FP_PATH_PARTS", "fp_filter"]

# Backward-compat alias (moved to blastradius.filters).
_fp_filter = fp_filter

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


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
        self,
        strategy: str = "github",
        max_targets: int = 20,
        min_stars: int = 100,
        scope: Optional[str] = None,
        iterations: int = 1,
        seed: int = 0,
    ) -> List[Dict]:
        """Hunt over up to ``max_targets`` discovered targets; returns result rows.

        When ``scope`` (a program name in the scope registry) is given, only
        in-scope targets are hunted. ``iterations`` repeats the hunt with a
        fixed ``seed`` (same-seed runs): a finding confirmed in k-of-N runs
        carries ``runs`` evidence instead of a single pass/fail, which dampens
        flaky network/timing outcomes.
        """
        import random

        random.seed(seed)
        merged: Dict[tuple, Dict] = {}
        for _ in range(max(1, iterations)):
            for row in self._run_once(strategy, max_targets, min_stars, scope):
                key = (row.get("repo"), row.get("report"))
                slot = merged.setdefault(key, {**row, "runs": 0})
                slot["runs"] += 1
                slot["confirmed"] = max(slot.get("confirmed", 0), row.get("confirmed", 0))
        results = sorted(merged.values(), key=lambda r: r.get("confirmed", 0), reverse=True)
        self._print_table(results)
        return results

    def _run_once(
        self,
        strategy: str,
        max_targets: int,
        min_stars: int,
        scope: Optional[str],
    ) -> List[Dict]:
        """One hunt pass; returns result rows."""
        targets = self.dork.find_targets(strategy, min_stars=min_stars)[:max_targets]
        if scope:
            from blastradius.scope import check_scope

            before = len(targets)
            targets = [t for t in targets if check_scope(t.get("url", ""), scope)["in_scope"]]
            print(f"[*] scope filter ({scope}): {before} -> {len(targets)} target(s)")
        if not targets:
            print(
                "[!] no targets discovered — set GITHUB_TOKEN (github strategy) / "
                "SHODAN_API_KEY (shodan) before hunting",
                file=sys.stderr,
            )
            return []

        results: List[Dict] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._hunt_one, t): t for t in targets}
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda r: r.get("confirmed", 0), reverse=True)
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
