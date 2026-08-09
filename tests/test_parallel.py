"""Parallel scanner + scan cache tests — no network."""

import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from blastradius.hunter.scanner import CVEHunter
from blastradius.scanners.cache import ScanCache
from blastradius.scanners.__main__ import main as scanners_main
from blastradius.scanners.parallel import ParallelScanner, validate_sandbox


@pytest.fixture
def repo(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.py").write_text(
            "name = request.args.get('name')\n"
            "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n",
            encoding="utf-8",
        )
    (tmp_path / "safe.py").write_text(
        "cur.execute('SELECT * FROM users WHERE name = %s', (name,))\n", encoding="utf-8"
    )
    return tmp_path


def test_parallel_matches_serial(repo):
    hunter = CVEHunter()
    serial = [f for f in hunter.scan_repo(str(repo)) if f.vuln_type == "sqli"]
    # serial baseline: compare against direct _scan_file over the same files
    direct = []
    for path in hunter._iter_files(str(repo)):
        direct.extend(hunter._scan_file(path))
    direct = [f for f in direct if f.vuln_type == "sqli"]
    assert len(serial) == len(direct) == 10
    assert hunter.files_scanned == 11  # 10 vuln files + safe.py


def test_parallel_progress_callback(repo):
    seen = []
    hunter = CVEHunter()
    findings = hunter.scan_repo(str(repo), progress=lambda f, n: seen.append(str(f)))
    assert len(seen) == 11  # callback fires for every file (incl. safe.py with 0 findings)
    assert len({f.file for f in findings}) == 10
    assert all(seen_path in {f.file for f in findings} for seen_path in seen
               if any(f.file == seen_path for f in findings))


def test_workers_auto_detected():
    scanner = ParallelScanner()
    assert 1 <= scanner.max_workers <= 8


def test_per_file_timeout_skips_hangs(tmp_path):
    def hang(path):
        time.sleep(5)
        return []

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scanner = ParallelScanner(timeout=1)
    results = scanner.scan_repo_parallel(str(tmp_path), hang, [tmp_path / "a.py"])
    assert results == []
    assert scanner.file_count == 1


def test_validate_parallel_with_fake_process_pool(repo, monkeypatch):
    class InlinePool:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def submit(self, fn, *args):
            from concurrent.futures import Future

            future = Future()
            future.set_result(fn(*args))
            return future

    monkeypatch.setattr("blastradius.scanners.parallel.ProcessPoolExecutor", InlinePool)
    hunter = CVEHunter()
    findings = [f for f in hunter.scan_repo(str(repo)) if f.vuln_type == "sqli"]
    results = ParallelScanner().validate_parallel(findings, validate_sandbox, max_workers=2)
    assert len(results) == len(findings)
    assert all(r[0].vuln_type == "sqli" for r in results)


# --- ScanCache ---------------------------------------------------------------


@pytest.fixture
def cache(tmp_path):
    return ScanCache(path=str(tmp_path / "cache.db"))


def test_cache_roundtrip(cache, tmp_path):
    from blastradius.hunter.scanner import Finding

    path = tmp_path / "app.py"
    path.write_text("x = 1\n", encoding="utf-8")
    finding = Finding(file=str(path), line=1, vuln_type="sqli", payload="q",
                      confidence=0.9, severity="HIGH", cwe="CWE-89",
                      description="d", remediation="r")
    assert cache.get_cached(path) is None
    cache.put(path, [finding])
    cached = cache.get_cached(path)
    assert cached and cached[0].vuln_type == "sqli"
    assert cached[0].confidence == 0.9


def test_cache_misses_on_change(cache, tmp_path):
    from blastradius.hunter.scanner import Finding

    path = tmp_path / "app.py"
    path.write_text("a = 1\n", encoding="utf-8")
    cache.put(path, [Finding(file=str(path), line=1, vuln_type="xss", payload="x",
                             confidence=0.8, severity="HIGH", cwe="CWE-79",
                             description="d", remediation="r")])
    path.write_text("a = 2\n", encoding="utf-8")  # content changed
    assert cache.get_cached(path) is None


def test_cache_ttl_expiry(tmp_path):
    cache = ScanCache(path=str(tmp_path / "c.db"), ttl_days=0)
    from blastradius.hunter.scanner import Finding

    path = tmp_path / "app.py"
    path.write_text("x\n", encoding="utf-8")
    cache.put(path, [Finding(file=str(path), line=1, vuln_type="sqli", payload="p",
                             confidence=0.9, severity="HIGH", cwe="CWE-89",
                             description="d", remediation="r")])
    assert cache.get_cached(path) is None  # expired immediately


def test_cache_used_by_parallel_scanner(tmp_path):
    from blastradius.hunter.scanner import Finding

    cache = ScanCache(path=str(tmp_path / "cache.db"))
    path = tmp_path / "app.py"
    path.write_text("x\n", encoding="utf-8")
    calls = {"n": 0}

    def scan_file(p):
        calls["n"] += 1
        return [Finding(file=str(p), line=1, vuln_type="sqli", payload="p",
                        confidence=0.9, severity="HIGH", cwe="CWE-89",
                        description="d", remediation="r")]

    scanner = ParallelScanner(cache=cache)
    scanner.scan_repo_parallel(str(tmp_path), scan_file, [path])
    scanner.scan_repo_parallel(str(tmp_path), scan_file, [path])
    assert calls["n"] == 1  # second pass served from cache


def test_cache_stats_and_clear(cache, tmp_path):
    from blastradius.hunter.scanner import Finding

    path = tmp_path / "app.py"
    path.write_text("x\n", encoding="utf-8")
    cache.put(path, [Finding(file=str(path), line=1, vuln_type="sqli", payload="p",
                             confidence=0.9, severity="HIGH", cwe="CWE-89",
                             description="d", remediation="r")])
    assert cache.stats()["cached_files"] == 1
    cache.clear()
    assert cache.stats()["cached_files"] == 0


def test_cache_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("blastradius.scanners.__main__.ScanCache",
                        lambda: ScanCache(path=str(tmp_path / "c.db")))
    rc = scanners_main(["cache", "stats"])
    assert rc == 0
    assert "Cached files" in capsys.readouterr().out
    assert scanners_main(["cache", "clear"]) == 0
