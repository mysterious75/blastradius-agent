"""BlastRadius master security agent — built-in, zero heavy dependencies.

The blueprint called for CAI orchestration, but cai-framework hard-requires
litellm[proxy] (~500MB / 100+ packages) for a tiny slice of API this module
actually uses (Agent + Runner + function_tool). This module implements that
slice directly on the openai SDK (already a core dependency) with an async
tool-calling loop, so the agent works out of the box with ``pip install -e "."``.

The agent drives the scanner tools, validates findings adversarially, and
reports with human-review flags. The LLM is resolved through the universal
provider system (blastradius.providers) — best available provider wins, and
any model the provider accepts can be used.
"""

import inspect
import json
import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from blastradius.providers.client import provider_api_key
from blastradius.providers.registry import PROVIDER_REGISTRY
from blastradius.providers.selector import auto_select
from blastradius.tools.patch_tool import generate_and_verify_patch
from blastradius.tools.prometheus_wrappers import (
    prometheus_adversarial_validate,
    prometheus_sqli_scan,
    prometheus_ssrf_scan,
    prometheus_xss_scan,
)
from blastradius.tools.sandbox_tool import run_exploit_sandbox

load_dotenv()

_selection = auto_select()
_PROVIDER = _selection["provider"] if _selection else "opencode_zen"
_MODEL = _selection["model"] if _selection else "deepseek-v4-flash"
_PROVIDER_CFG = PROVIDER_REGISTRY[_PROVIDER]
_API_KEY = provider_api_key(_PROVIDER)

MAX_ITERATIONS = int(os.getenv("BLASTRADIUS_AGENT_MAX_ITERATIONS", "25"))

SYSTEM_INSTRUCTIONS = (
    "You are an autonomous security engineer.\n"
    "1. Scan the given target for vulnerabilities using the provided "
    "Prometheus scanners (sqli, xss, ssrf).\n"
    "2. For each finding, run prometheus_adversarial_validate to filter "
    "out false positives.\n"
    "3. For every remaining finding, run run_exploit_sandbox with the "
    "vulnerable code to prove exploitability before reporting it.\n"
    "4. For exploitable findings, run generate_and_verify_patch to produce "
    "a verified patch.\n"
    "5. Report every confirmed finding with its payload, evidence, "
    "severity, remediation, and patch verification status.\n"
    "6. Never execute exploits against live targets outside an approved "
    "scope, and never auto-merge patches. Always flag for human review."
)

TOOLS = [
    prometheus_sqli_scan,
    prometheus_xss_scan,
    prometheus_ssrf_scan,
    prometheus_adversarial_validate,
    run_exploit_sandbox,
    generate_and_verify_patch,
]

_TYPE_MAP = {
    "str": "string",
    "float": "number",
    "int": "number",
    "bool": "boolean",
}


def _tool_schema(fn) -> dict:
    """Build an OpenAI function schema from a tool's signature + docstring."""
    sig = inspect.signature(fn)
    props: dict = {}
    required: list = []
    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        if param.default is not inspect.Parameter.empty:
            continue  # optional params: accept defaults, keep the schema lean
        kind = getattr(param.annotation, "__name__", "str")
        props[name] = {"type": _TYPE_MAP.get(kind, "string"), "description": f"{name}"}
        required.append(name)
    doc = inspect.getdoc(fn) or ""
    first = doc.strip().splitlines()[0] if doc.strip() else fn.__name__
    return {
        "type": "function",
        "function": {
            "name": fn.__name__,
            "description": first,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        },
    }


def build_agent(api_key=None) -> dict:
    """Create the agent definition (name, instructions, tools, client)."""
    client = AsyncOpenAI(
        api_key=api_key or _API_KEY,
        base_url=_PROVIDER_CFG["base_url"],
        default_headers=_PROVIDER_CFG.get("extra_headers") or {},
    )
    return {
        "name": "BlastRadius",
        "instructions": SYSTEM_INSTRUCTIONS,
        "tools": TOOLS,
        "model": os.getenv("CAI_MODEL", _MODEL),
        "client": client,
    }


async def _run_conversation(messages: list, agent: dict, max_iterations: int) -> str:
    """Bounded tool-calling loop over an existing message list.

    Shared by ``run_scan`` (one conversation per target) and the focused-task
    orchestrator (one small conversation per finding). Returns the final text
    answer, or the last assistant content when the iteration budget runs out.
    """
    client = agent["client"]
    tools = [_tool_schema(t) for t in agent["tools"]]
    seen_calls = set()
    last_content = ""
    for _ in range(max_iterations):
        response = await client.chat.completions.create(
            model=agent["model"], messages=messages, tools=tools
        )
        choice = response.choices[0]
        last_content = choice.message.content or ""
        if choice.finish_reason != "tool_calls" or not choice.message.tool_calls:
            return last_content
        messages.append(choice.message)  # assistant message carrying tool_calls
        for call in choice.message.tool_calls:
            fn = next((t for t in agent["tools"] if t.__name__ == call.function.name), None)
            if fn is None:
                result = f"unknown tool: {call.function.name}"
            else:
                key = f"{call.function.name}:{call.function.arguments}"
                if key in seen_calls:
                    # break infinite tool-call loops: identical repeat gets no new work
                    result = (
                        "repeated tool call with identical arguments — result unchanged; "
                        "stop calling this tool and write your final answer"
                    )
                else:
                    seen_calls.add(key)
                    try:
                        args = json.loads(call.function.arguments or "{}")
                        result = fn(**args)
                    except Exception as exc:  # a failed tool call must not kill the loop
                        result = f"error: {exc}"
            messages.append({"role": "tool", "tool_call_id": call.id, "content": str(result)})
    return (
        last_content
        or f"conversation exceeded {max_iterations} iterations — try a smaller task, "
        "or raise BLASTRADIUS_AGENT_MAX_ITERATIONS."
    )


async def run_scan(target: str, agent: dict = None) -> str:
    """Run the BlastRadius agent against a target and return its final output.

    One bounded conversation: sends the target plus the tool schemas, executes
    any tool calls the model requests, feeds the results back, and returns the
    final text answer. For large targets prefer ``run_focused_hunt`` (per-finding
    sub-tasks) instead. ``agent`` is injectable for tests.
    """
    agent = agent or build_agent()
    messages = [
        {"role": "system", "content": agent["instructions"]},
        {"role": "user", "content": target},
    ]
    return await _run_conversation(messages, agent, MAX_ITERATIONS)
