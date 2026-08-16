"""XXEScanner — self-contained XML External Entity detection.

Flags ET.parse / lxml.etree / SAXParser usage when defusedxml is not present.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    make_finding,
    references_variable,
    scan_lines,
)

_SINKS = [
    r"(?:xml\.etree\.ElementTree|\betree\b|\bET\b)\.(?:parse|fromstring|parseString|XML|iterparse)\s*\(",
    r"lxml\.etree\.(?:parse|fromstring|XML)\s*\(",
    r"xml\.dom\.minidom\.parse\s*\(",
    r"xml\.sax\.(?:parse|parseString)\s*\(",
]
_SAFE = re.compile(r"defusedxml|XMLParser\s*\([^)]*resolve_entities\s*=\s*False", re.I)


class XXEScanner:
    """Pattern-based XXE scanner."""

    name = "xxe"

    def detect(self, code: str, path=None):
        if _SAFE.search(code):
            return []
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not (references_variable(line) or has_source_flag):
                return None
            confidence = 0.8 if has_source_flag else 0.7
            return make_finding(
                path,
                idx,
                "xxe",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-611",
                "XML External Entity: XML parsed without defusedxml hardening.",
                "Parse XML with defusedxml or disable external entity resolution.",
            )

        return scan_lines(code, path, check)
