"""Agentic-eval harness tests — real corpus targets, real agent graph (no mocks)."""

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCH_DIR = _REPO_ROOT / "benchmarks"
_BENCH_MODULE = _BENCH_DIR / "agent_eval.py"


def _load_agent_eval():
    """Load benchmarks/agent_eval.py by path (benchmarks is not a package)."""
    spec = importlib.util.spec_from_file_location("agent_eval", _BENCH_MODULE)
    module = importlib.util.module_from_spec(spec)
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    spec.loader.exec_module(module)
    return module


def _corpus_dir_with(target_name: str) -> Path:
    """A temp corpus dir containing only the named real corpus target."""
    src = _BENCH_DIR / "corpus" / target_name
    tmp = Path(tempfile.mkdtemp(prefix="br-ae-corpus-"))
    shutil.copytree(src, tmp / target_name)
    return tmp


def _latest_report(out_dir: Path) -> dict:
    reports = sorted(out_dir.glob("agent_eval_*.json"))
    assert reports, "agent_eval JSON report was not written"
    return json.loads(reports[-1].read_text(encoding="utf-8"))


def test_agent_eval_scores_corpus():
    module = _load_agent_eval()
    out = Path(tempfile.mkdtemp(prefix="br-ae-out-"))
    try:
        code = module.main(
            [
                "--corpus",
                str(_BENCH_DIR / "corpus"),
                "--targets",
                "flask-sqli",
                "--out",
                str(out),
            ]
        )
        assert code == 0
        summary = _latest_report(out)
        assert summary["totals"]["detection_recall"] >= 1.0
        assert summary["totals"]["attack_success_rate"] >= 0.0
        # flask-sqli is proven in the sandbox, so its target row carries it.
        row = summary["targets"][0]
        assert row["target"] == "flask-sqli"
        assert row["expected"] == 1
        assert row["detection_recall"] == 1.0
    finally:
        shutil.rmtree(out, ignore_errors=True)


def test_gate():
    module = _load_agent_eval()
    out = Path(tempfile.mkdtemp(prefix="br-ae-gate-"))
    try:
        # sqli is sandbox-proven: a 1.0 attack-rate gate must pass.
        code = module.main(
            [
                "--corpus",
                str(_BENCH_DIR / "corpus"),
                "--targets",
                "flask-sqli",
                "--out",
                str(out),
                "--min-attack-rate",
                "1.0",
            ]
        )
        assert code == 0

        # hardcoded-secrets has no exploit template -> candidate-only, attack
        # success 0, so the same gate must fail closed (exit 1).
        tmp_corpus = _corpus_dir_with("hardcoded-secrets")
        try:
            code = module.main(
                [
                    "--corpus",
                    str(tmp_corpus),
                    "--out",
                    str(out),
                    "--min-attack-rate",
                    "1.0",
                ]
            )
            assert code == 1
        finally:
            shutil.rmtree(tmp_corpus, ignore_errors=True)
    finally:
        shutil.rmtree(out, ignore_errors=True)
