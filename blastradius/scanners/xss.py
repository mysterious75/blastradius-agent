"""XSSScanner — self-contained cross-site scripting detection.

Sinks: innerHTML, outerHTML, document.write, eval, dangerouslySetInnerHTML,
v-html, [innerHTML, insertAdjacentHTML, .html(), render_template_string.
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
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\bdocument\.write\s*\(",
    r"\bdocument\.writeln\s*\(",
    r"\beval\s*\(",
    r"\bdangerouslySetInnerHTML\b",
    r"\bv-html\b",
    r"\[innerHTML\]",
    r"\binsertAdjacentHTML\s*\(",
    r"\.html\s*\(",
    r"\brender_template_string\s*\(",
]
_SAFE = re.compile(
    r"htmlspecialchars|html\.escape|escapeHtml|html_escape|HTMLEscape|"
    r"sanitize|purify|DOMPurify|markupsafe|escapejs",
    re.I,
)


class XSSScanner:
    """Pattern-based cross-site scripting scanner."""

    name = "xss"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.7
            return make_finding(
                path,
                idx,
                "xss",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-79",
                "Cross-site scripting: unescaped input reaches an HTML/JS sink.",
                "Encode all dynamic output with context-aware escaping and apply a strict CSP.",
            )

        return scan_lines(code, path, check)
