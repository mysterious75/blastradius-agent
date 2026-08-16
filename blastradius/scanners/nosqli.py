"""NoSQLiScanner — self-contained NoSQL injection detection (CWE-943).

Flags MongoDB/PyMongo/Mongoose queries built from user input: find/findOne
filters containing request data, string concatenation into a query, $where /
$regex / $gt / $ne operator injection, and query dicts populated straight
from request/req/body values (the Rocket.Chat NoSQLi pattern). Safe markers
(escape/sanitize/validate/allowlist/parameterized, ObjectId wrapping) are
skipped. Candidate-only: no PoC template.
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
    r"\.find(?:One|_one)?\s*\([^)]*(?:request\.|req\.|ctx\.|body|params|data)",
    r"""\.find(?:One|_one)?\s*\([^)]*\+\s*[^\s'\"]""",
    r"\$where\s*:\s*[^,})]+(?:request|req|body|params|user|token|input)",
    r"query\s*=\s*\{[^}]*request\.|query\s*=\s*\{[^}]*req\.|filter\s*=\s*\{[^}]*request\.",
    r"(?:user|username|password|email|token)\s*:\s*(?:request\.|req\.|body\.|ctx\.)",
    r"\$(?:gt|ne|eq|regex|where)\s*:\s*(?:request\.|req\.|body\.)",
]
_SAFE = re.compile(
    r"escape|sanitize|validate|allowlist|parameterized|"
    r"ObjectId\s*\('\s*[A-Za-z_$][\w$]*",
    re.I,
)


class NoSQLiScanner:
    """Pattern-based NoSQL injection scanner."""

    name = "nosqli"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.75
            return make_finding(
                path,
                idx,
                "nosqli",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-943",
                "NoSQL injection: user input is interpolated into a MongoDB/PyMongo/Mongoose query.",
                "Validate and type-check user input (ObjectId wrapping, schema validation) before building queries; never pass raw input into $where or operator filters.",
            )

        return scan_lines(code, path, check)
