"""OWASP AI-agent security guardrails for the multi-agent graph.

Implements a subset of the OWASP AI Agent Security / LLM Top 10 controls:

- Agent tool allow-listing (``AGENT_TOOL_MATRIX``): each role is pinned to the
  tool prefixes it may call; anything else is out of scope for that role
  (least privilege, OWASP LLM01/agent tool abuse).
- Policy-violation output scanning (``validate_agent_output``): a size cap
  plus destructive-command markers, so structured output cannot smuggle
  ``rm -rf /`` onto the blackboard (structured-output hardening, OWASP LLM02).
- Prompt-injection scanning of repo content (``flag_repo_content``): untrusted
  repo text is flagged -- never silently trusted -- before it reaches an LLM
  (OWASP LLM01).
- Risk tiers (``risk_tier``): high-risk actions such as patch application,
  report publishing, or network-enabled exploitation require a human in the
  loop; read/scan actions run unattended (human-in-the-loop, OWASP agent
  autonomy / LLM10).

Everything here is offline and deterministic -- no LLM calls, no network.
"""

from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Agent -> allowed tool prefixes (least privilege per role)
# ---------------------------------------------------------------------------

AGENT_TOOL_MATRIX: Dict[str, List[str]] = {
    # Reconnaissance surface: read-only scanning/discovery, no mutations,
    # no execution and no writes outside the target's own repo.
    "recon": ["scan", "read", "grep", "list", "crawl"],
    # Exploitation only inside the sandbox -- no arbitrary host-side writes.
    "exploit": ["run_exploit_sandbox", "reconstruct"],
    # Patching: generate + verify only. No network, no shell outside sandbox.
    "patch": ["generate", "verify", "ast", "pytest"],
}

# Destructive/privilege-escaping markers that must never appear in agent
# output (case-insensitive scan).
POLICY_VIOLATION_MARKERS: List[str] = [
    "rm -rf",
    "rm -fr",
    "drop table",
    "drop database",
    "format c:",
    "del /s /q",
    "rd /s /q",
    "mkfs.",
    "chown -r 0 /",
    ":(){:|:&};:",  # fork bomb
    "dd if=/dev/zero",
]

# Prompt-injection phrases scanned on repo content before it reaches an LLM.
INJECTION_MARKERS: List[str] = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore prior instructions",
    "system prompt",
    "disregard",
    "developer mode",
    "you are now",
    "pretend you are",
    "jailbreak",
]

# Actions that must not run unattended (human-in-the-loop gate).
HIGH_RISK_ACTIONS = frozenset({"patch-apply", "report-publish", "exploit-with-network"})

DEFAULT_MAX_OUTPUT = 50_000


# ---------------------------------------------------------------------------
# Tool allow-listing
# ---------------------------------------------------------------------------


def allowed_tools(agent: str) -> List[str]:
    """Tool prefixes the given agent may call (empty = unknown agent)."""
    return list(AGENT_TOOL_MATRIX.get(agent, []))


# ---------------------------------------------------------------------------
# Output validation (structured-output hardening + size cap)
# ---------------------------------------------------------------------------


def validate_agent_output(
    agent: str, output: Any, max_len: int = DEFAULT_MAX_OUTPUT
) -> Tuple[bool, str]:
    """(ok, reason) for ``output`` produced by ``agent``.

    Returns ``(False, reason)`` when the output is larger than ``max_len``
    characters or contains a policy-violation marker; otherwise
    ``(True, "ok")``. Non-string output (structured payloads) is scanned via
    ``repr`` so dict/list artifacts get the same protection as text.
    """
    text = output if isinstance(output, str) else repr(output)
    size = len(text)
    if size > max_len:
        return False, f"output exceeds {max_len} char cap ({size} chars)"
    lowered = text.lower()
    for marker in POLICY_VIOLATION_MARKERS:
        if marker in lowered:
            return False, f"output contains policy-violation marker {marker!r}"
    return True, "ok"


# ---------------------------------------------------------------------------
# Prompt-injection scanning of repo content (flag, do not block)
# ---------------------------------------------------------------------------


def flag_repo_content(text: str) -> bool:
    """True when ``text`` contains a prompt-injection marker.

    Flagging lets callers annotate (e.g. ``injection_flag``) rather than block
    -- the content may be legitimate code, and the decision stays with the
    human-in-the-loop mechanics downstream.
    """
    lowered = text.lower()
    return any(marker in lowered for marker in INJECTION_MARKERS)


# ---------------------------------------------------------------------------
# Risk tiers (human-in-the-loop gating)
# ---------------------------------------------------------------------------


def risk_tier(agent: str, action: str) -> str:
    """Human-in-the-loop tier for ``action``: ``'low'`` or ``'high'``.

    ``patch-apply``, ``report-publish`` and ``exploit-with-network`` are high
    risk and must be gated on a human; read/scan-style actions are low.
    """
    return "high" if action in HIGH_RISK_ACTIONS else "low"


# ---------------------------------------------------------------------------
# Per-agent guard wrapper
# ---------------------------------------------------------------------------


class AgentGuard:
    """Binds the guardrail primitives to one named agent.

    Roles hold an ``AgentGuard`` instead of threading their name through every
    call, and the guard records the highest risk tier observed during the run
    so the orchestrator can expose ``risk_summary`` per agent.
    """

    def __init__(self, agent: str):
        self.agent = agent
        self._highest_risk: str = "low"

    def validate_output(self, output: Any, max_len: int = DEFAULT_MAX_OUTPUT) -> Tuple[bool, str]:
        """Delegate to :func:`validate_agent_output` bound to this agent."""
        return validate_agent_output(self.agent, output, max_len)

    def flag_repo_content(self, text: str) -> bool:
        """True when repo content fed to this agent carries an injection marker."""
        return flag_repo_content(text)

    def action_risk(self, action: str) -> str:
        """Tier for ``action``; records the highest tier observed this run."""
        tier = risk_tier(self.agent, action)
        if tier == "high":
            self._highest_risk = "high"
        return tier

    @property
    def highest_risk(self) -> str:
        """Highest risk tier observed for this agent during the run."""
        return self._highest_risk
