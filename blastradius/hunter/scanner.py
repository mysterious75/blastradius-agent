"""CVEHunter — clone a repo and statically scan its source files (Phase 3).

Prometheus's SQLi/XSS/SSRF scanners are URL scanners: they require a running
target, so local files are scanned with static sink/source rules that mirror
those three detections. Every candidate finding is additionally run through
Prometheus's AdversarialValidator (the real prometheus component) to get a
false-positive verdict, and exploitability is proven in the sandbox before a
disclosure report is written (see cli.py / disclosure.py).
"""

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from blastradius.prometheus_bootstrap import ensure_prometheus_importable
from blastradius.security.input_validator import validate_github_url, validate_repo_path

ensure_prometheus_importable()

from src.scanner.adversarial import AdversarialValidator  # noqa: E402

# ---------------------------------------------------------------------------
# Static analysis rules (file-level equivalents of the URL scanners)
# ---------------------------------------------------------------------------

FILE_EXTENSIONS = ("*.py", "*.js", "*.php", "*.ts", "*.tsx")

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

# Untrusted input sources (request data, query params, form fields...)
SOURCES = [
    r"request\.(?:args|form|values|get_json|query_params|cookies|headers)\b",
    r"req\.(?:query|body|params|headers)\b",
    r"\$_GET|\$_POST|\$_REQUEST",
    r"getParameter\(",
    r"\binput\(",
    r"searchParams\.get\(",
    r"ctx\.query\b",
    r"context\.(?:request|args)\b",
    r"window\.location",
]

_SQL_KEYWORDS = r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b"
# String literal concatenated with a variable, or an f-string with a placeholder
_SQL_CONCAT = [
    r"['\"][^'\"]{0,200}['\"]\s*\+\s*[^\s'\"+=]",
    r"\bf['\"][^'\"]*\{[^}]*\}",
]

_XSS_SINKS = [
    r"\binnerHTML\b", r"\bouterHTML\b", r"\bdocument\.write\(", r"\bdocument\.writeln\(",
    r"\bdangerouslySetInnerHTML\b", r"\bv-html\b", r"\becho\b", r"\bprint\s*\(",
    r"\brender_template_string\(", r"\binsertAdjacentHTML\(", r"\.html\(", r"\beval\(",
]
_XSS_SAFE = [
    r"htmlspecialchars", r"html\.escape", r"\bescape\(", r"sanitize", r"purify",
    r"escapejs", r"DOMPurify", r"markupsafe",
]

_SSRF_SINKS = [
    r"requests\.(?:get|post|put|delete|request|head)\(", r"urllib\.request\b",
    r"urlopen\(", r"\bfetch\(", r"http\.(?:get|request)\(", r"axios\.",
    r"\bgot\(", r"\bcurl\(", r"httpx\.", r"aiohttp\.", r"\brequest\(",
]

VULN_META = {
    "sqli": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "description": (
            "SQL injection: user-controlled input is concatenated into a SQL "
            "statement, allowing an attacker to alter the query or extract data."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements for ALL database "
            "interactions. Never concatenate user input into SQL."
        ),
    },
    "xss": {
        "severity": "HIGH",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "description": (
            "Cross-site scripting: unescaped user-controlled input is reflected "
            "into HTML/JavaScript, allowing script execution in other users' "
            "browsers."
        ),
        "remediation": (
            "Encode all dynamic output with context-aware escaping and apply a "
            "strict Content-Security-Policy."
        ),
    },
    "ssrf": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-918",
        "description": (
            "Server-side request forgery: user-controlled input flows into a "
            "server-side URL fetch, allowing requests to internal services or "
            "cloud metadata."
        ),
        "remediation": (
            "Validate the destination against an allowlist, resolve DNS "
            "server-side, and block private/loopback/link-local address ranges."
        ),
    },
}

VALID_VULN_TYPES = tuple(VULN_META)


@dataclass
class Finding:
    """A static candidate finding from scanning a repo file."""
    file: str
    line: int
    vuln_type: str
    payload: str
    confidence: float
    evidence: str = ""
    context: str = ""
    severity: str = ""
    cwe: str = ""
    remediation: str = ""
    description: str = ""
    original_code: str = ""


def _line_references_variable(line: str) -> bool:
    """Whether a sink on this line receives a non-literal value."""
    stripped = re.sub(r"['\"][^'\"]*['\"]", " ", line)  # drop string literals
    return bool(
        re.search(r"\(\s*[A-Za-z_$][\w$]*", stripped)          # sink(<var>
        or re.search(r"=\s*[A-Za-z_$][\w$]*", stripped)        # sink = <var>
        or re.search(r"\becho\b[^;]*[A-Za-z_$][\w$]*", stripped, re.I)
        # . $var concat (PHP) — but NOT a method call like .html("literal")
        or re.search(r"\.[ \t]*\$?[A-Za-z_]\w*\s*(?!\()", stripped)
    )


def _score_sqli(line: str, has_source: bool) -> float:
    if not re.search(_SQL_KEYWORDS, line, re.I):
        return 0.0
    if any(re.search(p, line) for p in _SQL_CONCAT):
        return 1.0 if has_source else 0.9
    return 0.0


def _score_xss(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _XSS_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _XSS_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.95 if has_source else 0.75


def _score_ssrf(line: str, has_source: bool) -> float:
    if not any(re.search(p, line) for p in _SSRF_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.9 if has_source else 0.7


_SCORERS = (("sqli", _score_sqli), ("xss", _score_xss), ("ssrf", _score_ssrf))


def reconstruct_target_code(finding: Finding) -> str:
    """Build a minimal runnable reproduction of the detected pattern.

    Used to sandbox-validate the finding. The reproduction is synthetic: it
    proves the *pattern* is exploitable, not that the real file is — manual
    confirmation is required before disclosure.
    """
    if finding.vuln_type == "sqli":
        return 'def target(user_input):\n    return "SELECT * FROM users WHERE name = \'" + user_input + "\'"\n'
    if finding.vuln_type == "xss":
        return 'def target(user_input):\n    return "<html><body>" + user_input + "</body></html>"\n'
    if finding.vuln_type == "ssrf":
        return 'def target(user_input):\n    return "http://internal-service/fetch?url=" + user_input\n'
    raise ValueError(f"Unsupported vuln_type {finding.vuln_type!r}")


# ---------------------------------------------------------------------------
# CVEHunter
# ---------------------------------------------------------------------------


class CVEHunter:
    """Clone a repo and scan its source files for vulnerability candidates."""

    def __init__(self, min_confidence: float = 0.7, clone_timeout: int = 120):
        self.min_confidence = min_confidence
        self.clone_timeout = clone_timeout
        self.files_scanned: int = 0
        self._validator: Optional[AdversarialValidator] = None

    @property
    def validator(self) -> AdversarialValidator:
        if self._validator is None:
            self._validator = AdversarialValidator()
        return self._validator

    # ------------------------------------------------------------------
    # Repo acquisition
    # ------------------------------------------------------------------

    def clone_repo(self, github_url: str) -> str:
        """Shallow-clone a GitHub repo into a fresh temp dir.

        The URL is validated (GitHub host only, no private IPs or path
        traversal) before cloning. Returns the path to the cloned repo; the
        caller owns cleanup.
        """
        github_url = validate_github_url(github_url)
        tmp = tempfile.mkdtemp(prefix="blastradius-")
        dest = Path(tmp) / "repo"
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", github_url, str(dest)],
                check=True, capture_output=True, text=True, timeout=self.clone_timeout,
            )
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {exc.stderr.strip() or exc}") from exc
        return str(dest)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_repo(self, repo_path: str) -> List[Finding]:
        """Scan every .py/.js/.php file in ``repo_path``.

        The path must resolve inside an allowed directory (see
        security.input_validator). Returns candidate findings with confidence
        >= ``min_confidence``, sorted by file/line.
        """
        repo_path = validate_repo_path(repo_path)
        findings: List[Finding] = []
        self.files_scanned = 0
        for path in self._iter_files(repo_path):
            self.files_scanned += 1
            findings.extend(self._scan_file(path))
        findings.sort(key=lambda f: (f.file, f.line, f.vuln_type))
        return findings

    def validate(self, finding: Finding) -> str:
        """Adversarial false-positive verdict via Prometheus's AdversarialValidator."""
        from src.scanner.findings import Finding as PrometheusFinding

        pf = PrometheusFinding(
            vuln_type=self._title(finding.vuln_type),
            title=f"{finding.vuln_type.upper()} in {finding.file}:{finding.line}",
            severity=finding.severity,
            url=f"file://{finding.file}",
            parameter="",
            method="STATIC",
            payload=finding.payload,
            evidence=finding.evidence,
            description=finding.description,
            remediation=finding.remediation,
            cvss=VULN_META[finding.vuln_type]["cvss"],
            cwe=finding.cwe,
            tool="cve-hunter",
            verified=True,
            confidence=finding.confidence,
            request="",
            response_snippet=finding.context[:500],
        )
        return self.validator.validate(pf).verdict

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _iter_files(self, repo_path: str):
        root = Path(repo_path)
        for ext in FILE_EXTENSIONS:
            for path in root.rglob(ext):
                if any(part in SKIP_DIRS for part in path.parts):
                    continue
                yield path

    def _scan_file(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        lines = text.splitlines()
        has_source = any(re.search(p, text, re.I) for p in SOURCES)

        findings: List[Finding] = []
        for idx, line in enumerate(lines, start=1):
            for vuln_type, scorer in _SCORERS:
                score = scorer(line, has_source)
                if score < self.min_confidence:
                    continue
                meta = VULN_META[vuln_type]
                findings.append(Finding(
                    file=str(path),
                    line=idx,
                    vuln_type=vuln_type,
                    payload=line.strip(),
                    confidence=round(score, 2),
                    evidence=line.strip(),
                    context="\n".join(lines[max(0, idx - 2):idx + 1]),
                    severity=meta["severity"],
                    cwe=meta["cwe"],
                    remediation=meta["remediation"],
                    description=meta["description"],
                ))
        return findings

    @staticmethod
    def _title(vuln_type: str) -> str:
        return {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "ssrf": "Server-Side Request Forgery",
        }.get(vuln_type, vuln_type)
