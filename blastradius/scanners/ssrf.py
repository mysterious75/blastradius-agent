"""SSRFScanner — self-contained server-side request forgery detection.

Sinks: requests.get(user_input), urllib.request, fetch(userInput),
axios(url), httpx, aiohttp, urlopen, curl.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    has_source,
    make_finding,
    references_variable,
    scan_lines,
)

_SINKS = [
    r"requests\.(?:get|post|put|delete|request|head)\s*\(",
    r"urllib\.request\b",
    r"urlopen\s*\(",
    r"\bfetch\s*\(",
    r"http\.(?:get|request)\s*\(",
    r"axios\.\w+\s*\(",
    r"\bgot\s*\(",
    r"\bcurl\s*\(",
    r"httpx\.\w+\s*\(",
    r"aiohttp\.\w+\s*\(",
]
_SAFE = re.compile(r"allowlist|validate|is_internal|is_private|check_url|blocked", re.I)


class SSRFScanner:
    """Pattern-based SSRF scanner."""

    name = "ssrf"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.7
            return make_finding(
                path, idx, "ssrf", line.strip(), confidence, "HIGH", "CWE-918",
                "Server-side request forgery: a variable reaches a server-side URL fetch.",
                "Validate the destination against an allowlist and block private/loopback ranges.",
            )

        return scan_lines(code, path, check)
