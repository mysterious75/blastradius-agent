"""SecretScanner — detection-only API-key / credential exposure scanning.

Finds high-signal API keys and credentials committed to code (CWE-798:
Use of Hard-coded Credentials). Detection ONLY — never validates or uses a
found key; the responsible flow is report -> owner revokes. Placeholder-ish
lines (examples, "your-", "xxxx") are skipped to avoid noise.
"""

import re

from blastradius.scanners._util import make_finding, scan_lines

_PATTERNS = [
    r"\bAIza[0-9A-Za-z\-_]{35}\b",          # Google API key
    r"\bsk-[A-Za-z0-9]{20,}\b",              # OpenAI
    r"\bghp_[A-Za-z0-9]{36}\b",              # GitHub personal access token
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",     # GitHub fine-grained PAT
    r"\bAKIA[0-9A-Z]{16}\b",                 # AWS access key id
    r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",    # Slack token
    r"\bsk_live_[A-Za-z0-9]{20,}\b",         # Stripe live key
]
_PLACEHOLDER = re.compile(
    r"example|your-|your_|xxxx|placeholder|changeme|sample|demo|<[a-z_]+>", re.I
)


class SecretScanner:
    """Pattern-based hard-coded credential detection."""

    name = "secret"

    def detect(self, code: str, path=None):
        def check(line, idx):
            if _PLACEHOLDER.search(line):
                return None
            if not any(re.search(p, line) for p in _PATTERNS):
                return None
            return make_finding(
                path, idx, "secret", line.strip(), 0.95, "HIGH", "CWE-798",
                "Hard-coded API key or credential exposed in source.",
                "Rotate the credential and remove it from the repository; load "
                "secrets from environment variables or a secret manager.",
            )

        return scan_lines(code, path, check)
