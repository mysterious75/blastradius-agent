"""BlastRadius master security agent (CAI orchestration).

Builds the autonomous security engineer agent from the blueprint: the agent
drives the Prometheus scanner tools, validates findings adversarially, and
reports with human-review flags. The LLM is resolved through the universal
provider system (blastradius.providers) — best available provider wins, and
any model the provider accepts can be used.
"""

import os

from dotenv import load_dotenv
from openai import AsyncOpenAI

try:
    from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, Runner

    CAI_AVAILABLE = True
except ImportError:  # cai-framework is optional — pip install -e ".[agent]"
    CAI_AVAILABLE = False
    Agent = None
    OpenAIChatCompletionsModel = None
    Runner = None
    print("CAI not installed. Run: pip install -e '.[agent]'")

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

# Resolve the best available provider + model from the environment.
_selection = auto_select()
_PROVIDER = _selection["provider"] if _selection else "opencode_zen"
_MODEL = _selection["model"] if _selection else "deepseek-v4-flash"
_PROVIDER_CFG = PROVIDER_REGISTRY[_PROVIDER]
_API_KEY = provider_api_key(_PROVIDER)

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
    # Model/endpoint resolved through the provider system (auto-select).
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CAI_MODEL", _MODEL),
        openai_client=AsyncOpenAI(
            api_key=_API_KEY,
            base_url=_PROVIDER_CFG["base_url"],
            default_headers=_PROVIDER_CFG.get("extra_headers") or {},
        ),
    ),
)


async def run_scan(target: str) -> str:
    """Run the BlastRadius agent against a target and return its final output."""
    result = await Runner.run(security_agent, target)
    return result.final_output
