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
    """Replace string-literal CONTENTS with spaces, preserving delimiters.

    A quote-aware scan is required: the naive regex stopped at a quote of the
    other kind, so ``'open(name, "r")'`` (a code sample stored in a string)
    still looked like a real ``open(`` call. That produced CI false positives
    on test fixtures and on the scanner's own PoC templates.
    """
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            if ch == "\\":
                out.append("  ")
                i += 2
                continue
            if ch == quote:
                quote = None
                out.append(ch)
            else:
                out.append(" ")
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def code_only(line: str) -> str:
    """Executable portion of a source line: literals and comments masked out."""
    masked = strip_literals(line)
    for marker in (" #", " //", "/*"):
        pos = masked.find(marker)
        if pos != -1:
            masked = masked[:pos]
    return masked


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


def first_arg_var(line: str) -> str:
    """First bare identifier passed to a sink call, or ``""``."""
    match = re.search(r"\(\s*([A-Za-z_$][\w$]*)", strip_literals(line))
    return match.group(1) if match else ""


def assigned_from_source(code: str, var: str) -> bool:
    """Whether ``var`` is assigned (anywhere in the file) from a source."""
    if not var:
        return False
    pattern = re.compile(
        rf"^\s*{re.escape(var)}\s*=\s*[^\n]*(?:{SOURCE_RE.pattern})",
        re.I | re.M,
    )
    return bool(pattern.search(code))


def make_finding(
    path, line, vuln_type, payload, confidence, severity, cwe, description, remediation
) -> Finding:
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
    """Run a per-line predicate returning Finding-or-None.

    Comment-only lines are skipped: documentation and commented-out code are
    not executed, so they must never produce a CI-gate finding.
    """
    findings = []
    in_docstring = None
    for idx, line in enumerate(code.splitlines(), start=1):
        stripped = line.lstrip()
        if in_docstring is not None:
            if in_docstring in line:
                in_docstring = None
            continue
        for quote in ('"""', "'''"):
            if stripped.startswith(quote):
                if quote not in stripped[len(quote) :]:
                    in_docstring = quote
                break
        else:
            quote = None
        if quote is not None and stripped.startswith(quote):
            continue
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue
        finding = predicate(line, idx)
        if finding is not None:
            findings.append(finding)
    return findings
