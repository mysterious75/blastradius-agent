"""SQLiScanner — self-contained SQL injection detection (no prometheus).

Detects string-concatenation SQL and raw SQL execution sinks, recognises
parameterized-query safe patterns, and scores confidence 0.0–1.0.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    has_source,
    make_finding,
    references_variable,
    scan_lines,
)

_SQL_KEYWORDS = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b", re.I)
_CONCAT = re.compile(r"['\"][^'\"]{0,200}['\"]\s*\+\s*[^\s'\"+=]")
_RAW_SINK = re.compile(
    r"\b(?:execute|executemany|executescript|raw|query|exec)\s*\("
    r"|sqlalchemy\.text\(|psycopg2\.connect\(|\.execute\(",
    re.I,
)
# Safe / parameterized markers
_PARAMETERIZED = re.compile(
    r"%s|%\([\w]+\)s|\?|:[\w]+|\$\d|setParameter\(|bind\(|"
    r"execute\([^)]*,[^)]*\)|format\(|params=|parameters=",
    re.I,
)


class SQLiScanner:
    """Pattern-based SQL injection scanner."""

    name = "sqli"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if not _SQL_KEYWORDS.search(line):
                return None
            if _PARAMETERIZED.search(line):
                return None  # safe pattern
            if _CONCAT.search(line) and (has_source(line) or has_source_flag):
                return make_finding(
                    path,
                    idx,
                    "sqli",
                    line.strip(),
                    0.95,
                    "CRITICAL",
                    "CWE-89",
                    "SQL injection: user input is concatenated into a SQL statement.",
                    "Use parameterized queries / prepared statements for all database interactions.",
                )
            if _RAW_SINK.search(line) and references_variable(line):
                return make_finding(
                    path,
                    idx,
                    "sqli",
                    line.strip(),
                    0.8,
                    "HIGH",
                    "CWE-89",
                    "Raw SQL execution with a variable argument; verify parameterization.",
                    "Use parameterized queries; avoid raw SQL execution with untrusted input.",
                )
            return None

        return scan_lines(code, path, check)
