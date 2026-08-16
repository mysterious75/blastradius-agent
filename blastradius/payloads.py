"""Real-world payload loading from the extracted HackerOne payload corpus.

Loads ``payloads/payload_corpus.json`` (repo-root data file, gitignored) and
serves de-duplicated, filtered payload lines grouped by weakness type so the
dynamic web scanner probes with payloads taken from real bug bounty reports
instead of synthetic ones.

The corpus file is located by walking up from this module to the repo root;
when it is missing or unreadable the module degrades gracefully to the
built-in defaults (or an empty list) and never raises.

Payload lines are kept only when they are usable as probes:
    * 3 <= len(payload) <= 80
    * printable ASCII only
    * no obvious placeholder text (``example.com``, ``<redacted>``, ``yourdomain``)

Entry points:
    xss_payloads()     -> reflected-XSS candidate lines (defaults always kept)
    sqli_payloads()    -> SQL-injection candidate lines
    command_payloads() -> command-injection candidate lines
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

# Current hardcoded defaults — the fallback for XSS when the corpus is gone.
DEFAULT_XSS_PAYLOADS: Tuple[str, ...] = (
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
)
# No pre-existing defaults exist for these types; they fall back to empty.
DEFAULT_SQLI_PAYLOADS: Tuple[str, ...] = ()
DEFAULT_COMMAND_PAYLOADS: Tuple[str, ...] = ()

# Weakness-bucket name substrings that identify each family (case-insensitive).
_BUCKET_PATTERNS: Dict[str, Tuple[str, ...]] = {
    "xss": ("xss", "cross-site"),
    "sqli": ("sql",),
    "command": ("command",),
}

_PLACEHOLDER_RE = re.compile(r"example\.com|<redacted>|yourdomain", re.IGNORECASE)
_MAX_REAL_PAYLOADS = 12


def _find_corpus_path() -> Path:
    """Repo-root corpus path, searching upward from this module's directory."""
    current = Path(__file__).resolve().parent
    for candidate in (current, *current.parents):
        path = candidate / "payloads" / "payload_corpus.json"
        if path.is_file():
            return path
    return current / "payloads" / "payload_corpus.json"


_corpus_path: Path = _find_corpus_path()


def _load_corpus(path: Path) -> Dict[str, List[str]]:
    """Return {weakness: [lines...]} from the corpus file, or {} if unavailable."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    corpus = data.get("corpus")
    if not isinstance(corpus, dict):
        return {}
    return corpus


def _is_usable(payload: str) -> bool:
    """A line is usable as a probe when it is short, printable ASCII, and real."""
    if not isinstance(payload, str):
        return False
    if not 3 <= len(payload) <= 80:
        return False
    if not all(32 <= ord(ch) < 127 for ch in payload):
        return False
    if _PLACEHOLDER_RE.search(payload):
        return False
    return True


def _real_payloads(kind: str) -> List[str]:
    """De-duplicated, filtered real payload lines for a weakness family."""
    corpus = _load_corpus(_corpus_path)
    if not corpus:
        return []
    patterns = _BUCKET_PATTERNS[kind]
    seen = set()
    result = []
    for weakness, lines in corpus.items():
        if not any(pattern in weakness.lower() for pattern in patterns):
            continue
        for line in lines:
            if not _is_usable(line) or line in seen:
                continue
            seen.add(line)
            result.append(line)
            if len(result) >= _MAX_REAL_PAYLOADS:
                return result
    return result


def _merged(defaults: Tuple[str, ...], real: List[str]) -> List[str]:
    """Defaults first, then real payloads — de-duplicated, order preserved."""
    result = list(defaults)
    for payload in real:
        if payload not in result:
            result.append(payload)
    return result


def xss_payloads() -> List[str]:
    """Real XSS probe lines (defaults + up to ~12 corpus lines)."""
    return _merged(DEFAULT_XSS_PAYLOADS, _real_payloads("xss"))


def sqli_payloads() -> List[str]:
    """Real SQL-injection probe lines, or [] when the corpus is unavailable."""
    return _merged(DEFAULT_SQLI_PAYLOADS, _real_payloads("sqli"))


def command_payloads() -> List[str]:
    """Real command-injection probe lines, or [] when the corpus is unavailable."""
    return _merged(DEFAULT_COMMAND_PAYLOADS, _real_payloads("command"))
