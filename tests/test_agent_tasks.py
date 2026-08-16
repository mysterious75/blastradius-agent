"""Focused sub-task orchestrator tests — scan + chat completions mocked."""

import pytest

from blastradius.agent_tasks import run_focused_hunt, run_focused_task
from blastradius.hunter.scanner import Finding


class Call:
    def __init__(self, name, arguments, call_id="call_1"):
        self.function = type("F", (), {"name": name, "arguments": arguments})()
        self.id = call_id


class Msg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class Choice:
    def __init__(self, finish_reason, message):
        self.finish_reason = finish_reason
        self.message = message


class Resp:
    def __init__(self, choice):
        self.choices = [choice]


class FakeCompletions:
    def __init__(self, content):
        self.content = content

    async def create(self, **kwargs):
        return Resp(Choice("stop", Msg(content=self.content)))


class FakeChat:
    def __init__(self, content):
        self.completions = FakeCompletions(content)


class FakeClient:
    def __init__(self, content):
        self.chat = FakeChat(content)


def _agent(content="CONFIRMED_EXPLOITABLE: the pattern is exploitable"):
    return {
        "name": "T",
        "instructions": "instruct",
        "tools": [],
        "model": "m",
        "client": FakeClient(content),
    }


def _finding(file="app.py", line=5, vuln_type="sqli", confidence=0.9, severity="CRITICAL"):
    return Finding(
        file=file,
        line=line,
        vuln_type=vuln_type,
        payload="q = '...' + x",
        confidence=confidence,
        severity=severity,
        description="SQL injection",
    )


@pytest.mark.anyio
async def test_run_focused_task_returns_verdict():
    # deterministic sandbox: sqli reconstruction is exploitable — no LLM call
    task = await run_focused_task(_finding(), agent=_agent())
    assert task["verdict"] == "exploitable"
    assert task["sandbox_verdict"] == "exploitable"
    assert task["llm_output"] == ""
    assert task["finding"] == ("app.py", 5, "sqli")
    assert task["file"] == "app.py" and task["line"] == 5


@pytest.mark.anyio
async def test_run_focused_task_not_exploitable():
    # jwt reconstruction has no target() function -> sandbox NOT_EXPLOITABLE
    task = await run_focused_task(_finding(vuln_type="jwt"), agent=_agent())
    assert task["verdict"] == "not_exploitable"
    assert task["sandbox_verdict"] == "not_exploitable"


@pytest.mark.anyio
async def test_run_focused_task_uses_llm_when_sandbox_inconclusive(monkeypatch):
    # inconclusive sandbox -> LLM reasoning task decides
    monkeypatch.setattr(
        "blastradius.agent_tasks.run_exploit_sandbox",
        lambda vuln_type, code: "sandbox could not decide",
    )
    task = await run_focused_task(_finding(), agent=_agent("NOT_EXPLOITABLE: escaped output"))
    assert task["sandbox_verdict"] == "needs_manual_review"
    assert task["verdict"] == "not_exploitable"  # from the LLM output
    assert task["llm_output"] != ""


@pytest.mark.anyio
async def test_run_focused_hunt_scan_rank_tasks_rerank(monkeypatch):
    findings = [
        _finding("a.py", 1, "sqli", 0.9, "CRITICAL"),
        _finding("b.py", 2, "xss", 0.95, "HIGH"),
        _finding("c.py", 3, "ssrf", 0.8, "MEDIUM"),
    ]

    async def fake_task(f, agent=None, max_iterations=8):
        return {
            "finding": (f.file, f.line, f.vuln_type),
            "file": f.file,
            "line": f.line,
            "vuln_type": f.vuln_type,
            "output": "CONFIRMED_EXPLOITABLE: yes" if f.file != "b.py" else "NOT_EXPLOITABLE: no",
            "verdict": "exploitable" if f.file != "b.py" else "not_exploitable",
        }

    monkeypatch.setattr("blastradius.agent_tasks.run_focused_task", fake_task)

    result = await run_focused_hunt(".", top_k=2, agent=_agent(), scan_repo=lambda _: findings)

    assert result["total_findings"] == 3
    assert result["top_k"] == 2
    assert len(result["tasks"]) == 2
    # top-2 by pre-verdict rank: a.py (0.9 critical) then b.py (0.95 high)
    assert result["tasks"][0]["file"] == "a.py"
    assert result["tasks"][1]["file"] == "b.py"
    # re-rank: b.py ruled out drops below c.py (which is still unverified but not disproven)
    re_files = [r.file for r in result["re_ranked"]]
    assert re_files.index("b.py") > re_files.index("c.py")


@pytest.mark.anyio
async def test_run_focused_hunt_empty_repo():
    result = await run_focused_hunt(".", agent=_agent(), scan_repo=lambda _: [])
    assert result["total_findings"] == 0
    assert result["tasks"] == []
    assert result["ranked"] == []


@pytest.mark.anyio
async def test_focused_tasks_run_concurrently(monkeypatch):
    import asyncio

    findings = [_finding(f"{c}.py", 1, "sqli", 0.9, "HIGH") for c in "abc"]
    state = {"active": 0, "max_active": 0}

    async def slow_task(f, agent=None, max_iterations=8):
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        await asyncio.sleep(0.02)
        state["active"] -= 1
        return {
            "finding": (f.file, f.line, f.vuln_type),
            "file": f.file,
            "line": f.line,
            "vuln_type": f.vuln_type,
            "output": "CONFIRMED_EXPLOITABLE: yes",
            "verdict": "exploitable",
        }

    monkeypatch.setattr("blastradius.agent_tasks.run_focused_task", slow_task)
    result = await run_focused_hunt(".", top_k=3, agent=_agent(), scan_repo=lambda _: findings)
    assert state["max_active"] > 1  # at least two tasks overlapped (parallel)
    assert len(result["tasks"]) == 3
