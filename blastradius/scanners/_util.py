"""Shared helpers for the self-contained scanners."""

import re
from typing import List

from blastradius.hunter.scanner import Finding

# Untrusted input source markers (line-level)
SOURCE_RE = re.compile(
    r"request\.(?:args|form|values|get_json|cookies|headers)\b"
    r"|req\.(?:query|body|params|headers)\b"
    r"|\$_GET|\$_POST|\$_REQUEST"
    r"|getParameter\(|r\.FormValue\(|\binput\(|searchParams\.get\("
    r"|params\[|ctx\.query\b|context\.(?:request|args)\b",
    re.I,
)


def strip_literals(line: str) -> str:
    return re.sub(r"['\"][^'\"]*['\"]", " ", line)


def references_variable(line: str) -> bool:
    """Whether a sink line receives a non-literal value."""
    stripped = strip_literals(line)
    return bool(
        re.search(r"\(\s*[A-Za-z_$][\w$]*", stripped)
        or re.search(r"=\s*[A-Za-z_$][\w$]*", stripped)
        or re.search(r"\.[ \t]*\$?[A-Za-z_]\w*(?![\w(])", stripped)
    )


def has_source(line: str) -> bool:
    return bool(SOURCE_RE.search(line))


def code_has_source(code: str) -> bool:
    return bool(SOURCE_RE.search(code))


def make_finding(path, line, vuln_type, payload, confidence, severity, cwe,
                 description, remediation) -> Finding:
    return Finding(
        file=str(path or ""),
        line=line,
        vuln_type=vuln_type,
        payload=payload,
        confidence=confidence,
        evidence=payload,
        severity=severity,
        cwe=cwe,
        description=description,
        remediation=remediation,
    )


def scan_lines(code: str, path, predicate) -> List[Finding]:
    """Run a per-line predicate returning Finding-or-None."""
    findings = []
    for idx, line in enumerate(code.splitlines(), start=1):
        finding = predicate(line, idx)
        if finding is not None:
            findings.append(finding)
    return findings
