"""DeserializationScanner — self-contained insecure deserialization detection.

Sinks: pickle/cPickle/dill/shelve loads, marshal.loads, yaml.load (unsafe),
Ruby Marshal.load / YAML.load, PHP unserialize / phar://, Java
ObjectInputStream.readObject / XMLDecoder, Go gob decode. Safe markers
(safe_load, SafeLoader, Loader=..., restricted unpicklers, JSON) are skipped.
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
    r"\b(?:pickle|cPickle|dill|shelve)\s*\.\s*(?:loads|load)\s*\(",
    r"\bmarshal\s*\.\s*(?:loads|load)\s*\(",
    r"\byaml\.load\s*\(",
    r"\bMarshal\.load\s*\(",
    r"\bYAML\.load\s*\(",
    r"\bunserialize\s*\(",
    r"\bphar://",
    r"ObjectInputStream[^;]*\.readObject\s*\(",
    r"\bXMLDecoder\s*\(",
    r"gob\.NewDecoder\s*\([^)]*\)\.Decode\s*\(",
]
_SAFE = re.compile(
    r"safe_load|SafeLoader|CSafeLoader|FullLoader|"
    r"yaml\.load\s*\([^,)]*,\s*Loader\s*=|"
    r"restricted_unpickler|find_class\s*=|permitted_classes|"
    r"json\.loads?\s*\(|json\.parse\s*\(|SimpleJSON|"
    r"Marshal\.dump\b|pickle\.dump\b|dill\.dump\b",
    re.I,
)


class DeserializationScanner:
    """Pattern-based insecure deserialization scanner."""

    name = "deserialization"

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
                path,
                idx,
                "deserialization",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-502",
                "Insecure deserialization: untrusted input reaches a deserializer.",
                "Never deserialize untrusted input; use safe loaders or restricted unpicklers.",
            )

        return scan_lines(code, path, check)
