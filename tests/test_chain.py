"""Directed exploit-path chaining tests (NodeZero-style multi-hop links)."""

import shutil
import tempfile
from pathlib import Path

from blastradius.agents.blackboard import Blackboard
from blastradius.agents.orchestrator import AgentGraph
from blastradius.agents.roles import CHAIN_RULES, ExploitAgent

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus"


def _confirmed(blackboard: Blackboard, vuln_type: str, file: str, line: int) -> None:
    blackboard.post(
        "exploit",
        "confirmed",
        {
            "file": file,
            "line": line,
            "vuln_type": vuln_type,
            "severity": "HIGH",
            "payload": "x",
            "confidence": 1.0,
            "sandbox": "CONFIRMED_EXPLOITABLE",
        },
    )


def test_multi_hop_chain():
    """Confirmed ssrf -> secret and sqli -> idor pairs get directed links."""
    blackboard = Blackboard()
    _confirmed(blackboard, "ssrf", "fetch.py", 10)
    _confirmed(blackboard, "secret", "config.py", 5)
    _confirmed(blackboard, "sqli", "db.py", 20)
    _confirmed(blackboard, "idor", "api.py", 30)

    ExploitAgent()._link_chains(blackboard)

    links = blackboard.directed_chains()
    by_type = {(link["from"]["vuln_type"], link["to"]["vuln_type"]): link for link in links}
    assert ("ssrf", "secret") in by_type, by_type
    assert ("sqli", "idor") in by_type, by_type
    ssrf_link = by_type[("ssrf", "secret")]
    assert ssrf_link["kind"] == "dependency"
    assert ssrf_link["from"]["file"] == "fetch.py"
    assert ssrf_link["to"]["file"] == "config.py"
    assert ssrf_link["note"] == "SSRF can reach internal endpoints that leak secrets or bypass auth"


def test_no_chain_for_unrelated():
    """Confirmed findings with no matching rule stay unlinked."""
    blackboard = Blackboard()
    _confirmed(blackboard, "sqli", "db.py", 1)
    _confirmed(blackboard, "xss", "app.js", 2)

    ExploitAgent()._link_chains(blackboard)

    assert blackboard.directed_chains() == []


def test_chains_in_result():
    """AgentGraph exposes chains_directed; runs clean on a multi-type repo."""
    tmp = Path(tempfile.mkdtemp(prefix="br-chain-"))
    try:
        for name in ("flask-sqli", "flask-xss"):
            src = CORPUS / name
            for item in src.iterdir():
                if item.name == "manifest.json":
                    continue
                dst = tmp / item.name
                if item.is_dir():
                    shutil.copytree(item, dst)
                else:
                    shutil.copy2(item, dst)
        result = AgentGraph().run(str(tmp))
        assert isinstance(result.chains_directed, list)
        types = {e.payload.get("vuln_type") for e in result.events if e.kind == "confirmed"}
        # Every emitted link must match a CHAIN_RULES edge between confirmed types.
        rule_edges = {(rule["from"], target) for rule in CHAIN_RULES for target in rule["to"]}
        for link in result.chains_directed:
            assert (link["from"]["vuln_type"], link["to"]["vuln_type"]) in rule_edges
            assert link["from"]["vuln_type"] in types and link["to"]["vuln_type"] in types
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
