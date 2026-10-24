"""Secret-aware redaction for CI gate logs, errors, evidence, and reports.

Repository content is untrusted; API keys and tokens must never reach logs,
notifications, or third parties in raw form.
"""

from __future__ import annotations

import os
import re
from typing import List, Tuple

# NOTE on boundaries: the leading guard is (?<![a-zA-Z]) instead of \b on
# purpose — secret names almost always arrive glued to identifier prefixes
# (db_password, my_api_key, user_session). A bare \b misses those because _
# is a word character, and a missed secret is a leak while an over-redacted
# identifier is harmless. Trailing \b stays so "secretary" is not flagged.
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{10,}")),
    ("openai-key", re.compile(r"sk-(?!ant-)[A-Za-z0-9\-_]{10,}")),
    (
        "generic-api-key",
        re.compile(
            r"(?i)(?<![a-zA-Z])(api[_-]?key|apikey)\b\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{12,})"
        ),
    ),
    ("bearer", re.compile(r"(?i)(?<![a-zA-Z])bearer\s+[A-Za-z0-9\-_.~+/=]{8,}")),
    (
        "cookie-session",
        re.compile(
            r"(?i)(?<![a-zA-Z])(session|sessionid|sid|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{8,})"
        ),
    ),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "github-token",
        re.compile(r"\b(?:ghp|ghs|ghu|ghr|github_pat)_[A-Za-z0-9_]{10,}"),
    ),
    (
        "webhook",
        re.compile(
            r"https://(?:hooks\.slack\.com|discord\.com/api/webhooks|outlook\.office\.com)[^\s\"']*"
        ),
    ),
    (
        "password",
        re.compile(
            r"(?i)(?<![a-zA-Z])(password|passwd|pwd|secret)\b\s*[:=]\s*['\"]?([^\s\"',;}]{4,})"
        ),
    ),
]

_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENCODE_API_KEY",
    "GITHUB_TOKEN",
    "SLACK_WEBHOOK_URL",
    "TEAMS_WEBHOOK_URL",
    "SMTP_PASS",
)


def redact_secrets(text: str) -> str:
    """Replace secret-shaped values with [REDACTED]; never raises."""
    if not text:
        return text
    out = text
    for _name, pattern in _PATTERNS:

        def _mask(match: re.Match) -> str:
            full = match.group(0)
            if match.lastindex and match.lastindex >= 2:
                return full[: match.start(2) - match.start(0)] + "[REDACTED]"
            return "[REDACTED]"

        try:
            out = pattern.sub(_mask, out)
        except Exception:
            continue
    for env_name in _ENV_NAMES:
        value = os.getenv(env_name, "")
        if value and len(value) >= 8 and value in out:
            out = out.replace(value, "[REDACTED]")
    return out
