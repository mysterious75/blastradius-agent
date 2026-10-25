"""Performance + scope-index regression tests for the static scanner.

The 20-repo study found a 16k-line generated data module taking ~920s because
``has_enclosing_function`` re-scanned upward for every sink candidate. These
tests pin the O(1) prefix index and the "don't evaluate taint for a zero score"
guard.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from blastradius.hunter.scanner import CVEHunter
from blastradius.taint import _find_func_start


def _large_data_module(lines: int) -> str:
    body = "\n".join(f"ENTRY_{i} = (0x{i:04x}, 'value-{i}')" for i in range(lines))
    return body + "\n"


def test_large_top_level_module_scans_in_linear_time(tmp_path):
    (tmp_path / "data.py").write_text(_large_data_module(8000), encoding="utf-8")
    started = time.perf_counter()
    findings = CVEHunter().scan_repo(str(tmp_path))
    elapsed = time.perf_counter() - started
    assert findings == []
    # Old implementation was ~200s here; keep a wide margin for slow CI runners.
    assert elapsed < 8.0, f"quadratic regression: {elapsed:.2f}s for 8000 lines"


@pytest.mark.unit
def test_find_func_start_matches_linear_scan_semantics():
    lines = [
        "x = 1",  # 0: top level
        "def outer():",  # 1
        "    y = 2",
        "    def inner():",  # 3
        "        return y",
        "    return inner()",
        "z = 3",  # 6: top level again
    ]
    assert _find_func_start(lines, 0) is None
    assert _find_func_start(lines, 1) is None  # sink line itself is skipped
    assert _find_func_start(lines, 2) == 1
    assert _find_func_start(lines, 4) == 3
    assert _find_func_start(lines, 6) == 3  # still inside outer


@pytest.mark.unit
def test_func_index_does_not_leak_between_line_lists():
    first = ["def a():", "    x = 1"]
    second = ["y = 0", "def b():", "    z = 2"]
    assert _find_func_start(first, 1) == 0
    assert _find_func_start(second, 2) == 1
    assert _find_func_start(first, 1) == 0


@pytest.mark.integration
def test_large_file_with_one_sink_stays_bounded(tmp_path):
    code = _large_data_module(6000) + ("def run(user_input):\n    os.system(user_input)\n")
    (tmp_path / "data.py").write_text(code, encoding="utf-8")
    started = time.perf_counter()
    findings = CVEHunter().scan_repo(str(tmp_path))
    elapsed = time.perf_counter() - started
    assert [f.vuln_type for f in findings] == ["cmd_injection"]
    assert elapsed < 8.0, f"quadratic regression: {elapsed:.2f}s for 6000 lines"


@pytest.mark.e2e
def test_cli_scans_generated_module_end_to_end(tmp_path):
    (tmp_path / "data.py").write_text(_large_data_module(4000), encoding="utf-8")
    env = dict(os.environ)
    env["BLASTRADIUS_HOME"] = str(tmp_path / ".home")
    env["PYTHONIOENCODING"] = "utf-8"
    repo_root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "blastradius.hunter", "--target", str(tmp_path)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "0 candidate finding" in result.stdout
