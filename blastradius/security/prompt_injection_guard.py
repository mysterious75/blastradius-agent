"""Prompt injection guard — scan code before it ever reaches an LLM.

Detected patterns cause a rule-based fallback only; the attempt is logged.
"""

import re
from typing import List, Tuple

INJECTION_PATTERNS = [
    r"ignore\s+(all|any|the)?\s*(previous|prior|above|earlier)\s*(instructions?|prompts?|messages?)",
    r"ignore\s+(your\s+)?(system\s+)?prompt",
    r"you\s+are\s+now\s+(a|an)?",
    r"system\s*:",
    r"disregard\s+(all|any)?\s*(previous|prior)?\s*instructions?",
    r"new\s+instructions?",
    r"jailbreak",
    r"override\s+(your\s+)?(system\s+)?(instructions?|prompt)",
]


def detect_injection(code: str) -> List[str]:
    """Patterns found in the code (empty = clean)."""
    return [p for p in INJECTION_PATTERNS if re.search(p, code, re.I)]


def guard_llm_call(code: str) -> Tuple[bool, str]:
    """(safe, reason) — False means the code must NOT reach an LLM."""
    found = detect_injection(code)
    if found:
        return False, "prompt injection detected: " + "; ".join(found)
    return True, "ok"


def log_attempt(code: str, context: str = "") -> None:
    """Record a blocked prompt-injection attempt to the audit log."""
    try:
        from blastradius.security.audit_log import AuditLogger

        AuditLogger().log("prompt_injection_attempt", context=context,
                          patterns=detect_injection(code))
    except Exception:
        pass
