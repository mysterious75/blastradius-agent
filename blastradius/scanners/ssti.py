"""SSTIScanner — self-contained server-side template injection detection.

Sinks: render_template_string(user), jinja2 Environment().from_string(user).
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
    r"render_template_string\s*\(",
    r"Environment\s*\(\s*\).*from_string\s*\(",
    r"\bTemplate\s*\(",
]
_SAFE = re.compile(r"autoescape|env\.autoescape|finalize|SandboxedEnvironment", re.I)


class SSTIScanner:
    """Pattern-based SSTI scanner."""

    name = "ssti"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.9 if (has_source(line) or has_source_flag) else 0.75
            return make_finding(
                path, idx, "ssti", line.strip(), confidence, "CRITICAL", "CWE-1336",
                "Server-side template injection: user input reaches a template renderer.",
                "Never render user input as the template source; use template variables only.",
            )

        return scan_lines(code, path, check)
