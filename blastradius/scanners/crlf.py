"""CRLFScanner — self-contained CRLF / header injection detection.

Sinks: header setters, header value concatenation, and SMTP/email fields
receiving user input that may carry CR/LF. Sanitizing calls are skipped.
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
    r"\b(?:set_header|add_header|send_header|append_header|setHeader|addHeader)\s*\(",
    r"\bHeader\s*\([^)]*[A-Za-z_$][\w$]*,",
    r"\bLocation\s*:\s*[^\"'\n]*[A-Za-z_$]",
    r"sendmail\s*\([^)]*[A-Za-z_$]",
    r"\bmsg\[\s*['\"][^'\"]*['\"]\s*\]\s*=\s*[A-Za-z_$]",
    r"\bheaders?\s*\[[^]]*\]\s*=[^=]",
    r"\.headers?\s*\.\s*set\s*\(",
]
_SAFE = re.compile(r"quote|escape|sanitize|strip|validate|encode", re.I)


class CRLFScanner:
    """Pattern-based CRLF injection scanner."""

    name = "crlf"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.8 if (has_source(line) or has_source_flag) else 0.7
            return make_finding(
                path,
                idx,
                "crlf",
                line.strip(),
                confidence,
                "MEDIUM",
                "CWE-93",
                "CRLF injection: user input with newlines reaches a header or email field.",
                "Strip/encode CR and LF from user input before headers or email fields.",
            )

        return scan_lines(code, path, check)
