"""PatchGenerator — produces a security patch for a finding.

Primary path: direct call to the OpenCode DeepSeek V4 Flash endpoint
(OpenAI-compatible chat completions at https://opencode.ai/zen/go/v1, no CAI,
no framework; api key from OPENCODE_API_KEY). Fallback: deterministic
rule-based patches per vulnerability type, applied when the API is
unavailable.

The patched code keeps the sandbox contract ``def target(user_input) -> str``
so the verification loop (syntax / exploit / regression) can run against it.
"""

import difflib
import json
import os
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional

from blastradius.hunter.scanner import Finding
from blastradius.security.input_validator import validate_target_code

PATCH_RULES = {
    "sqli": "SQL Injection: use parameterized queries (prepared statements) only.",
    "xss": "XSS: escape output with html.escape() or template-engine auto-escaping.",
    "ssrf": "SSRF: validate the destination URL against an allowlist (https only) before fetching.",
    "traversal": "Path traversal: resolve with os.path.abspath and reject paths outside a known root.",
}

# Hardened replacements per vuln type — keep target(user_input) -> str.
_RULE_PATCHES = {
    "sqli": '''def target(user_input):
    return "SELECT * FROM users WHERE name = '" + user_input.replace("'", "''") + "'"
''',
    "xss": '''import html

def target(user_input):
    return "<html><body>" + html.escape(user_input) + "</body></html>"
''',
    "ssrf": '''def target(user_input):
    if not user_input.startswith("https://"):
        return "blocked"
    return "http://internal-service/fetch?url=" + user_input
''',
    "traversal": '''import os

def target(user_input):
    path = os.path.abspath(user_input)
    root = os.path.abspath("/safe")
    if not path.startswith(root):
        return "blocked"
    return path
''',
}

_RULE_EXPLANATIONS = {
    "sqli": "Escaped single quotes ('') so input cannot break out of the SQL string literal; prefer parameterized queries where a DB API is available.",
    "xss": "Escaped all dynamic output with html.escape() so injected scripts cannot execute.",
    "ssrf": "Rejected any destination that is not https:// (allowlist) before it reaches the fetch.",
    "traversal": "Resolved the path with os.path.abspath and rejected anything outside the safe root.",
}

API_URL = os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/zen/go/v1/chat/completions")
DEFAULT_MODEL = "deepseek-v4-flash"


def _make_diff(original: str, patched: str) -> str:
    return "\n".join(difflib.unified_diff(
        original.splitlines(),
        patched.splitlines(),
        fromfile="original",
        tofile="patched",
        lineterm="",
    ))


@dataclass
class Patch:
    """A generated security patch."""
    original_code: str
    patched_code: str
    diff: str = ""
    explanation: str = ""
    source: str = "rule"  # "api" | "rule"

    def __post_init__(self):
        if not self.diff:
            self.diff = _make_diff(self.original_code, self.patched_code)


class PatchGenerator:
    """Generate patches via the OpenCode DeepSeek V4 Flash endpoint, falling
    back to rule-based patches.

    Endpoint: https://opencode.ai/zen/go/v1/chat/completions (OpenAI-compatible,
    provider "@ai-sdk/openai-compatible"). API key comes from OPENCODE_API_KEY.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL, timeout: int = 30):
        self.api_key = api_key or os.getenv("OPENCODE_API_KEY")
        self.model = os.getenv("OPENCODE_MODEL", model)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_patch(self, finding: Finding, failure_context: str = "") -> Patch:
        """Generate a patch for ``finding``.

        ``failure_context`` (optional) contains prior verification failures and
        is forwarded to the model so it can correct the patch.
        """
        try:
            return self._generate_via_api(finding, failure_context)
        except Exception:
            return self._rule_based_patch(finding)

    # ------------------------------------------------------------------
    # DeepSeek API path
    # ------------------------------------------------------------------

    def _generate_via_api(self, finding: Finding, failure_context: str) -> Patch:
        if not self.api_key:
            raise RuntimeError("OPENCODE_API_KEY not set; falling back to rule-based patch")
        # Hardening: never forward code that could carry prompt injection or
        # exceed size limits; the caller falls back to rule-based patching.
        validate_target_code(finding.original_code or finding.payload)
        payload = self._build_messages(finding, failure_context)
        data = self._http_post(payload)
        content = data["choices"][0]["message"]["content"]
        return self._parse_patch_response(content, finding)

    def _build_messages(self, finding: Finding, failure_context: str) -> Dict:
        rules = "\n".join(f"- {k}: {v}" for k, v in PATCH_RULES.items())
        system = (
            "You are a security patch generator. Fix the vulnerability in the provided Python code.\n"
            f"Rules per vulnerability type:\n{rules}\n"
            "Keep the function signature `def target(user_input)` returning a string, and do not "
            "change behavior for benign input.\n"
            "Respond with ONLY JSON: {\"patched_code\": \"<full patched python code>\", "
            "\"explanation\": \"<what you changed and why>\"}."
        )
        user = (
            f"Vulnerability type: {finding.vuln_type}\n"
            f"Original code:\n```python\n{finding.original_code or finding.payload}\n```"
        )
        if failure_context:
            user += f"\nPrevious verification failures (fix these):\n{failure_context}"
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }

    def _http_post(self, payload: Dict) -> Dict:
        """POST to the DeepSeek chat completions endpoint; returns parsed JSON."""
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _parse_patch_response(self, content: str, finding: Finding) -> Patch:
        content = content.strip()
        content = re.sub(r"^```\w*\n?", "", content)
        content = re.sub(r"\n?```$", "", content)
        try:
            data = json.loads(content)
            patched = data["patched_code"]
            explanation = data.get("explanation", "")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError("model response was not JSON containing patched_code") from exc
        return Patch(
            original_code=finding.original_code or finding.payload,
            patched_code=patched,
            explanation=explanation,
            source="api",
        )

    # ------------------------------------------------------------------
    # Rule-based fallback
    # ------------------------------------------------------------------

    def _rule_based_patch(self, finding: Finding) -> Patch:
        original = finding.original_code or finding.payload
        if finding.vuln_type not in _RULE_PATCHES:
            return Patch(
                original_code=original,
                patched_code=original,
                explanation=f"No patch rule for vuln_type {finding.vuln_type!r}.",
                source="rule",
            )
        return Patch(
            original_code=original,
            patched_code=_RULE_PATCHES[finding.vuln_type],
            explanation=_RULE_EXPLANATIONS[finding.vuln_type],
            source="rule",
        )
