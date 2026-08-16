"""ProtoPollutionScanner — JavaScript prototype pollution detection.

Sinks: __proto__ / constructor.prototype / Object.prototype property
injection, and recursive-merge utilities fed with user data (lodash/_.merge,
deep-merge). Safe markers (hasOwnProperty guards, Object.freeze,
structuredClone) are skipped. Candidate-only: no PoC template.
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
    r"__proto__",
    r"constructor\.prototype",
    r"Object\.prototype",
    r"\.merge\s*\([^)]*(?:user|body|params|req|input|data)",
    r"merge\s*=\s*\(.*\)\s*=>",
]
_SAFE = re.compile(
    r"hasOwnProperty\s*\(\s*['\"]__proto__"
    r"|hasOwnProperty\s*\.\s*call\s*\([^)]*['\"]__proto__"
    r"|Object\.freeze"
    r"|structuredClone",
    re.I,
)


class ProtoPollutionScanner:
    """Pattern-based JavaScript prototype pollution scanner."""

    name = "proto_pollution"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if not any(re.search(p, line) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.75
            return make_finding(
                path,
                idx,
                "proto_pollution",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-1321",
                "Prototype pollution: user-controlled input reaches a prototype "
                "assignment or recursive-merge utility (_.merge), allowing "
                "attacker-controlled properties to be injected onto Object.prototype.",
                "Reject '__proto__'/'constructor'/'prototype' keys from user input, "
                "use Object.freeze / structuredClone, and sanitize keys inside "
                "recursive merge functions.",
            )

        return scan_lines(code, path, check)
