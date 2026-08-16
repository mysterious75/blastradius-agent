"""ParallelScanner — thread-parallel file scanning + process-parallel validation.

- scan_repo_parallel: ThreadPoolExecutor over files (I/O + regex bound)
- validate_parallel: ProcessPoolExecutor for sandbox validation (CPU bound)
- per-file timeout (30s default); progress callback on_file_scanned(file, n)
- worker count auto-sized from CPU count
"""

import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

DEFAULT_TIMEOUT = 30


def _default_workers(max_workers: Optional[int]) -> int:
    if max_workers:
        return max_workers
    cpus = os.cpu_count() or 4
    return min(8, max(1, cpus))


def validate_sandbox(finding):
    """Module-level (picklable) sandbox validator for process pools."""
    from blastradius.hunter.scanner import reconstruct_target_code
    from blastradius.tools.sandbox_tool import run_exploit_sandbox

    result = run_exploit_sandbox(finding.vuln_type, reconstruct_target_code(finding))
    return finding, result


class ParallelScanner:
    """Scan files in parallel with an optional findings cache."""

    def __init__(
        self,
        max_workers: Optional[int] = None,
        timeout: int = DEFAULT_TIMEOUT,
        progress: Optional[Callable] = None,
        cache=None,
    ):
        self.max_workers = _default_workers(max_workers)
        self.timeout = timeout
        self.progress = progress  # on_file_scanned(file, findings_count)
        self.cache = cache  # optional ScanCache
        self.file_count = 0

    # ------------------------------------------------------------------
    # File scanning (threads)
    # ------------------------------------------------------------------

    def scan_repo_parallel(self, repo_path, scan_file: Callable, iter_files) -> List:
        """scan_file(path) -> List[Finding]; iter_files yields file paths."""
        files = list(iter_files)
        self.file_count = len(files)
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_one, scan_file, path): path for path in files}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    findings = future.result(timeout=self.timeout)
                except Exception:
                    findings = []  # skip files that hang or error
                results.extend(findings)
                if self.progress is not None:
                    self.progress(path, len(findings))
        return results

    def _scan_one(self, scan_file: Callable, path):
        if self.cache is not None:
            cached = self.cache.get_cached(path)
            if cached is not None:
                return cached
        findings = scan_file(path)
        if self.cache is not None and findings:
            self.cache.put(path, findings)
        return findings

    # ------------------------------------------------------------------
    # Sandbox validation (processes)
    # ------------------------------------------------------------------

    def validate_parallel(
        self, findings, validate: Callable, max_workers: Optional[int] = None
    ) -> List:
        """Run validate(finding) in a process pool; returns list of results."""
        if not findings:
            return []
        workers = _default_workers(max_workers)
        results = []
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(validate, f): f for f in findings}
            for future in as_completed(futures):
                try:
                    results.append(future.result(timeout=self.timeout))
                except Exception:
                    continue
        return results
