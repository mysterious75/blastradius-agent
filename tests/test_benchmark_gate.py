"""Precision-floor gate tests for benchmarks/run.py (offline, one corpus target)."""

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RUN = _REPO_ROOT / "benchmarks" / "run.py"

pytestmark = [pytest.mark.unit, pytest.mark.integration]


def _load_run():
    spec = importlib.util.spec_from_file_location("benchmark_run", _RUN)
    module = importlib.util.module_from_spec(spec)
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    spec.loader.exec_module(module)
    return module


def test_gate_failures_reports_both_floors():
    module = _load_run()
    failures = module._gate_failures(f1=0.4, precision=0.5, min_f1=0.5, min_precision=0.8)
    assert any("F1" in item for item in failures)
    assert any("precision" in item for item in failures)
    assert module._gate_failures(1.0, 1.0, 0.5, 0.8) == []


def test_cli_precision_floor(tmp_path):
    module = _load_run()
    corpus = tmp_path / "corpus"
    shutil.copytree(_REPO_ROOT / "benchmarks" / "corpus" / "flask-sqli", corpus / "flask-sqli")
    out = tmp_path / "out"

    assert module.main(["--corpus", str(corpus), "--out", str(out)]) == 0
    assert (out / "BENCHMARK.md").is_file()
    assert module.main(["--corpus", str(corpus), "--out", str(out), "--min-precision", "1.01"]) == 1
