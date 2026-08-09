"""BlastRadius master security agent (CAI orchestration).

Builds the autonomous security engineer agent from the blueprint: the agent
drives the Prometheus scanner tools, validates findings adversarially, and
reports with human-review flags. Requires cai-framework and a DeepSeek key.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, Runner

from blastradius.tools.patch_tool import generate_and_verify_patch
from blastradius.tools.prometheus_wrappers import (
    prometheus_adversarial_validate,
    prometheus_sqli_scan,
    prometheus_ssrf_scan,
    prometheus_xss_scan,
)
from blastradius.tools.sandbox_tool import run_exploit_sandbox

load_dotenv()

security_agent = Agent(
    name="BlastRadius",
    instructions=(
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
    ),
    tools=[
        prometheus_sqli_scan,
        prometheus_xss_scan,
        prometheus_ssrf_scan,
        prometheus_adversarial_validate,
        run_exploit_sandbox,
        generate_and_verify_patch,
    ],
    # OpenCode DeepSeek V4 Flash endpoint (OpenAI-compatible,
    # provider "@ai-sdk/openai-compatible"). The SDK base_url appends
    # /chat/completions, resolving to the OpenCode endpoint.
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", "deepseek-v4-flash"),
        openai_client=AsyncOpenAI(
            api_key=os.getenv("OPENCODE_API_KEY"),
            base_url=os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/zen/go/v1"),
        ),
    ),
)


async def run_scan(target: str) -> str:
    """Run the BlastRadius agent against a target and return its final output."""
    result = await Runner.run(security_agent, target)
    return result.final_output
