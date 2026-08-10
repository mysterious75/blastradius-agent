"""Built-in agent loop tests — chat completions mocked, no network, no CAI."""

import pytest

from blastradius.agent import _tool_schema, run_scan


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
    def __init__(self, responses):
        self.responses = list(responses)
        self.seen_messages = []

    async def create(self, **kwargs):
        self.seen_messages.append(kwargs["messages"])
        return self.responses.pop(0)


class FakeChat:
    def __init__(self, responses):
        self.completions = FakeCompletions(responses)


class FakeClient:
    def __init__(self, responses):
        self.chat = FakeChat(responses)


def dummy_tool(target: str) -> str:
    """Scan the target."""
    return f"scanned:{target}"


def _agent(responses):
    return {
        "name": "T",
        "instructions": "instruct",
        "tools": [dummy_tool],
        "model": "m",
        "client": FakeClient(responses),
    }


@pytest.mark.anyio
async def test_run_scan_executes_tool_calls_and_returns_final():
    agent = _agent([
        Resp(Choice("tool_calls", Msg(tool_calls=[Call("dummy_tool", '{"target": "x"}')]))),
        Resp(Choice("stop", Msg(content="done"))),
    ])
    assert await run_scan("go", agent) == "done"
    # the tool result was fed back to the model
    last = agent["client"].chat.completions.seen_messages[-1]
    assert last[-1]["role"] == "tool"
    assert last[-1]["content"] == "scanned:x"


@pytest.mark.anyio
async def test_run_scan_unknown_tool_does_not_crash():
    agent = _agent([
        Resp(Choice("tool_calls", Msg(tool_calls=[Call("nope", "{}")]))),
        Resp(Choice("stop", Msg(content="final"))),
    ])
    assert await run_scan("go", agent) == "final"
    last = agent["client"].chat.completions.seen_messages[-1]
    assert "unknown tool: nope" in last[-1]["content"]


@pytest.mark.anyio
async def test_run_scan_bad_tool_args_does_not_crash():
    agent = _agent([
        Resp(Choice("tool_calls", Msg(tool_calls=[Call("dummy_tool", "not-json")]))),
        Resp(Choice("stop", Msg(content="final"))),
    ])
    assert await run_scan("go", agent) == "final"


@pytest.mark.anyio
async def test_run_scan_plain_answer_returns_directly():
    agent = _agent([Resp(Choice("stop", Msg(content="no tools needed")))])

    assert await run_scan("go", agent) == "no tools needed"
    assert agent["client"].chat.completions.seen_messages[-1][-1]["role"] == "user"


def test_tool_schema_marks_required_params():
    schema = _tool_schema(dummy_tool)
    assert schema["function"]["name"] == "dummy_tool"
    assert schema["function"]["parameters"]["required"] == ["target"]
    assert schema["function"]["parameters"]["properties"]["target"]["type"] == "string"
