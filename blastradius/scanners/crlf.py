"""CRLFScanner — self-contained CRLF / header injection detection.

Sinks: header setters, header value concatenation, and SMTP/email fields
receiving user input that may carry CR/LF. Sanitizing calls are skipped. A
sink is only flagged when the header VALUE is user-derived (assignment-chain
taint check) or the line literally embeds CR/LF escapes next to a variable —
so ``headers['Authorization'] = f'Bearer {token}'`` with token from config is
NOT flagged.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    has_source,
    make_finding,
    references_variable,
    scan_lines,
)
from blastradius.taint import is_var_tainted, sink_arg_var

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
_CRLF_ESCAPE = re.compile(r"\\[rn]", re.I)


def _value_var(line: str) -> str:
    """Identifier carrying the header value (RHS after ``=`` for assignment
    sinks; the sink-arg variable for header-setter calls)."""
    m = re.search(r"=\s*([A-Za-z_$][\w$]*)", line)
    if m:
        return m.group(1)
    return sink_arg_var(line)


def _builds_crlf(line: str) -> bool:
    """Line embeds a CR/LF escape literal AND a variable."""
    if not _CRLF_ESCAPE.search(line):
        return False
    stripped = re.sub(r"(['\"])(?:\\.|(?!\1)[^\\])*?\1", " ", line)
    return bool(re.search(r"[A-Za-z_$][\w$]*", stripped))


class CRLFScanner:
    """Pattern-based CRLF injection scanner."""

    name = "crlf"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)
        all_lines = code.splitlines()

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            # Header value must be user-derived (assignment-chain taint check)
            # or the line must literally build CR/LF from input.
            tainted = has_source(line) or has_source_flag
            if not tainted:
                var = _value_var(line)
                tainted = bool(var) and is_var_tainted(all_lines, idx - 1, var)
            if not tainted and _builds_crlf(line):
                tainted = True
            if not tainted:
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
