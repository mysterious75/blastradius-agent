"""Tests for scripts/ingest_snapshot.py (offline mode only)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ingest_snapshot


def test_offline_build_writes_snapshot(tmp_path):
    ingest = Path(__file__).resolve().parents[1] / "data" / "ingest"
    if not (ingest / "defillama_protocols.json").is_file():
        return  # snapshot data absent — skip silently
    rc = ingest_snapshot.main(["--ingest-dir", str(ingest), "--out-dir", str(tmp_path)])
    assert rc == 0
    out = json.loads((tmp_path / "blast-graph.json").read_text(encoding="utf-8"))
    assert out["provenance"]["node_count"] > 100
    assert len(out["graph"]["nodes"]) == out["provenance"]["node_count"]
    assert "disclaimer" in out["provenance"]
    assert any("snapshot:" in n for n in out["provenance"]["inputs"])


def test_empty_ingest_dir_still_writes(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    outdir = tmp_path / "out"
    rc = ingest_snapshot.main(["--ingest-dir", str(empty), "--out-dir", str(outdir)])
    assert rc == 0
    out = json.loads((outdir / "blast-graph.json").read_text(encoding="utf-8"))
    assert out["provenance"]["node_count"] >= 0
