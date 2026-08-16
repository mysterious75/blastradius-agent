"""Agent graph tests — offline against a real vulnerable target (no mocks)."""

import concurrent.futures
import shutil
import tempfile
from pathlib import Path

from blastradius.agents.blackboard import Blackboard
from blastradius.agents.orchestrator import AgentGraph
from blastradius.agents.roles import ExploitAgent, ReconAgent

CORPUS = (
    Path(__file__).resolve().parent.parent
    / "benchmarks"
    / "corpus"
    / "flask-sqli"
)


def _vuln_copy() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="br-agents-"))
    for item in CORPUS.iterdir():
        if item.name == "manifest.json":
            continue
        shutil.copy2(item, tmp / item.name)
    return tmp


def test_recon_posts_candidates():
    tmp = _vuln_copy()
    try:
        blackboard = Blackboard()
        recon = ReconAgent()
        count = recon.run(blackboard, str(tmp))
        assert count >= 1
        assert all(e.kind == "candidate" for e in blackboard.candidates())
        assert blackboard.candidates()[0].payload["vuln_type"] == "sqli"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_graph_end_to_end():
    tmp = _vuln_copy()
    try:
        result = AgentGraph().run(str(tmp))
        assert result.candidates, "sqli candidate must be discovered"
        assert result.confirmed, "sqli candidate must be proven in the sandbox"
        assert result.patches, "confirmed finding must get a patch"
        assert result.agents == ["recon", "exploit", "patch"]
        assert result.files_scanned >= 1
        kinds = {e.kind for e in result.events}
        assert {"candidate", "confirmed"}.issubset(kinds)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_exploit_agent_parallel_posts():
    blackboard = Blackboard()

    def worker(i):
        for _ in range(50):
            blackboard.post("exploit", "confirmed", {"i": i})

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    assert len(blackboard.confirmed()) == 400
    assert blackboard.summary()["confirmed"] == 400


def test_chain_linking_same_file():
    blackboard = Blackboard()
    for line in (1, 2):
        blackboard.post(
            "exploit",
            "confirmed",
            {"file": "app.py", "line": line, "vuln_type": "sqli"},
        )
    ExploitAgent()._link_chains(blackboard)
    assert len(blackboard.chains()) == 1
    assert blackboard.chains()[0]["file"] == "app.py"
    assert len(blackboard.chains()[0]["members"]) == 2
