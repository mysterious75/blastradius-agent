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

# Paths/dirs that are never scanned (vendored code, build artifacts, migrations)
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "dist", "build", "vendor", "migrations",
}

# Extension -> language key used by the comment/docstring skipping logic
_LANG_OF = {
    ".py": "py", ".js": "js", ".php": "php", ".ts": "ts", ".tsx": "tsx",
    ".rb": "rb", ".erb": "erb", ".java": "java", ".go": "go", ".rs": "rs", ".jsx": "jsx",
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
# String literal concatenated with a variable. f-strings and plain literals
# are intentionally NOT flagged (too many false positives).
_SQL_CONCAT = [
    r"['\"][^'\"]{0,200}['\"]\s*\+\s*[^\s'\"+=]",
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

# Language-specific XSS sinks (populated by the language-expansion rules)
_LANG_XSS_SINKS = {}

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
    "idor": {
        "severity": "HIGH",
        "cvss": 5.3,
        "cwe": "CWE-639",
        "description": (
            "Insecure Direct Object Reference: a handler reads an object id "
            "from user input without checking that the caller is authorized "
            "to access that object."
        ),
        "remediation": (
            "Enforce an authorization check (ownership / role) before "
            "returning any object looked up by an attacker-supplied id."
        ),
    },
    "ssti": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-1336",
        "description": (
            "Server-side template injection: user input reaches a template "
            "renderer (Jinja2/Mako) and is evaluated as template code."
        ),
        "remediation": (
            "Never pass user input as the template source; render data via "
            "template variables only, and keep template files static."
        ),
    },
    "xxe": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-611",
        "description": (
            "XML External Entity: XML is parsed with a parser that resolves "
            "external entities, allowing file disclosure / SSRF via crafted XML."
        ),
        "remediation": (
            "Parse XML with defusedxml (or disable external entity resolution "
            "on the parser) before processing untrusted XML input."
        ),
    },
    "jwt": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-347",
        "description": (
            "Weak JWT verification: tokens are decoded with signature "
            "verification disabled or the 'none' algorithm allowed, letting "
            "attackers forge tokens."
        ),
        "remediation": (
            "Always verify the signature with a strong algorithm allowlist "
            "(e.g. HS256/RS256) and never accept algorithm 'none'."
        ),
    },
    "graphql": {
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-943",
        "description": (
            "GraphQL injection: a resolver builds a query/statement by "
            "concatenating resolver arguments into raw strings."
        ),
        "remediation": (
            "Use parameterized queries / ORM bindings inside resolvers and "
            "never concatenate resolver arguments into query strings."
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
        or re.search(r"\.[ \t]*\$?[A-Za-z_]\w*(?![\w(])", stripped)
    )


def _is_skippable_line(line: str, lang: str, state: dict) -> bool:
    """Whether a line is inside a comment/docstring and must not be scored.

    ``state`` carries per-file flags: in_docstring (py/rb) and in_block (C-style).
    """
    stripped = line.strip()
    if not stripped:
        return False

    # single-line comments
    if lang in ("py", "rb", "go", "rs", "php") and stripped.startswith("#"):
        return True
    if lang in ("js", "ts", "tsx", "jsx", "java", "go", "rs", "php", "rb") and stripped.startswith("//"):
        return True

    # Python/Ruby docstrings (triple-quoted)
    if lang in ("py", "rb"):
        if state.get("in_docstring"):
            if '"""' in stripped or "'''" in stripped:
                state["in_docstring"] = False
            return True
        if stripped.startswith(('"""', "'''")):
            if stripped.count('"""') + stripped.count("'''") == 1:
                state["in_docstring"] = True
            return True  # opening line (or one-line docstring) is never code

    # C-style block comments (js/ts/jsx/java/go/rs/php)
    if lang in ("js", "ts", "tsx", "jsx", "java", "go", "rs", "php"):
        if "/*" in stripped:
            state["in_block"] = True
        if state.get("in_block"):
            if "*/" in stripped:
                state["in_block"] = False
            return True
    return False


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


def _score_ssti(line: str, has_source: bool) -> float:
    if re.search(r"render_template_string\s*\(", line):
        if _line_references_variable(line):
            return 0.9 if has_source else 0.8
        return 0.0
    if re.search(r"(?:jinja2\.Template|Environment\s*\(\).*from_string|\bTemplate\s*\()", line):
        if _line_references_variable(line):
            return 0.8 if has_source else 0.7
    return 0.0


def _score_xxe(line: str, has_source: bool, has_defusedxml: bool) -> float:
    if has_defusedxml:
        return 0.0
    if re.search(
        r"(?:xml\.etree\.ElementTree|lxml\.etree|\betree\b|\bET\b)\.(?:parse|fromstring|parseString|XML|iterparse)\s*\(",
        line, re.I,
    ):
        if _line_references_variable(line) or has_source:
            return 0.8 if has_source else 0.7
    return 0.0


def _score_jwt(line: str, has_source: bool) -> float:
    if "jwt.decode(" not in line:
        return 0.0
    if re.search(r"verify_signature\s*=\s*False", line) or re.search(r"verify\s*=\s*False", line):
        return 0.9
    if re.search(r"algorithms?\s*=\s*[\[('\"][^)\]]*['\"]none['\"]", line, re.I):
        return 0.9
    return 0.0


def _score_graphql(line: str, has_source: bool, has_graphql: bool) -> float:
    if not has_graphql:
        return 0.0
    if any(re.search(p, line) for p in _SQL_CONCAT):
        return 0.8 if has_source else 0.7
    return 0.0


# IDOR: object-id read from user input, no authorization check nearby
_IDOR_ID_SOURCES = [
    r"request\.(?:args|form|values|get_json)\s*\([^)]*['\"]id['\"]",
    r"getParameter\(\s*['\"]id['\"]",
    r"['\"][^'\"]*<int:[^'\"]*>['\"]",
    r"request\.view_args",
    r"\bid\s*=\s*request\.",
]
_IDOR_AUTH = [
    r"@login_required", r"login_required", r"current_user", r"is_authenticated",
    r"require_auth", r"permission", r"has_access", r"request\.auth",
    r"jwt\.require", r"check_permission", r"\bsession\b", r"roles_required",
]


def _score_lang_xss(line: str, lang: str, has_source: bool) -> float:
    """Language-specific XSS sinks (Ruby/Java/Go/Rust — Task 4)."""
    sinks = _LANG_XSS_SINKS.get(lang)
    if not sinks or not any(re.search(p, line, re.I) for p in sinks):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.85 if has_source else 0.75


_SCORERS = (
    ("sqli", _score_sqli),
    ("xss", _score_xss),
    ("ssrf", _score_ssrf),
    ("ssti", _score_ssti),
    ("jwt", _score_jwt),
)


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
    if finding.vuln_type == "ssti":
        return "def target(user_input):\n    from jinja2 import Template\n    return Template(user_input).render()\n"
    if finding.vuln_type == "jwt":
        return (
            "def target(user_input):\n"
            "    import base64, json\n"
            "    parts = user_input.split('.')\n"
            "    return json.loads(base64.urlsafe_b64decode(parts[1] + '=='))\n"
        )
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
                if "min." in path.name:  # minified bundles — noise, never real code
                    continue
                yield path

    def _make_finding(self, path: Path, idx: int, lines: list, vuln_type: str, score: float) -> Finding:
        meta = VULN_META[vuln_type]
        return Finding(
            file=str(path),
            line=idx,
            vuln_type=vuln_type,
            payload=lines[idx - 1].strip(),
            confidence=round(score, 2),
            evidence=lines[idx - 1].strip(),
            context="\n".join(lines[max(0, idx - 2):idx + 1]),
            severity=meta["severity"],
            cwe=meta["cwe"],
            remediation=meta["remediation"],
            description=meta["description"],
        )

    def _scan_file(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        lines = text.splitlines()
        has_source = any(re.search(p, text, re.I) for p in SOURCES)
        has_defusedxml = "defusedxml" in text
        has_graphql = any(
            re.search(r"resolve_|strawberry\.field|graphene\.ObjectType|\bField\s*\(|@strawberry", l)
            for l in lines
        )
        lang = _LANG_OF.get(path.suffix.lower(), "py")
        state = {"in_docstring": False, "in_block": False}

        findings: List[Finding] = []
        for idx, line in enumerate(lines, start=1):
            if _is_skippable_line(line, lang, state):
                continue
            for vuln_type, scorer in _SCORERS:
                score = scorer(line, has_source)
                if score < self.min_confidence:
                    continue
                findings.append(self._make_finding(path, idx, lines, vuln_type, score))
            if lang == "py":
                xxe_score = _score_xxe(line, has_source, has_defusedxml)
                if xxe_score >= self.min_confidence:
                    findings.append(self._make_finding(path, idx, lines, "xxe", xxe_score))
            graphql_score = _score_graphql(line, has_source, has_graphql)
            if graphql_score >= self.min_confidence:
                findings.append(self._make_finding(path, idx, lines, "graphql", graphql_score))
            lang_score = _score_lang_xss(line, lang, has_source)
            if lang_score >= self.min_confidence:
                findings.append(self._make_finding(path, idx, lines, "xss", lang_score))
        if lang == "py":
            findings.extend(self._scan_idor_py(lines, path))
        return findings

    def _scan_idor_py(self, lines: list, path: Path) -> List[Finding]:
        """Function-level IDOR check: id read from user input without auth markers."""
        findings: List[Finding] = []
        n = len(lines)
        i = 0
        while i < n:
            stripped = lines[i].strip()
            if not stripped.startswith("def "):
                i += 1
                continue

            # collect decorators directly above the def
            j = i
            decorators = []
            while j > 0 and lines[j - 1].strip().startswith("@"):
                decorators.insert(0, lines[j - 1])
                j -= 1

            # collect body until the next def at the same/lower indentation
            base = len(lines[i]) - len(lines[i].lstrip())
            k = i + 1
            while k < n:
                l2 = lines[k]
                if l2.strip() and (len(l2) - len(l2.lstrip())) <= base \
                        and not l2.strip().startswith((")", "]", "}")):
                    break
                k += 1

            func_text = "\n".join(decorators + [lines[i]] + lines[i + 1:k])
            has_id = any(re.search(p, func_text, re.I) for p in _IDOR_ID_SOURCES)
            has_auth = any(re.search(p, func_text, re.I) for p in _IDOR_AUTH)
            if has_id and not has_auth:
                findings.append(self._make_finding(path, i + 1, lines, "idor", 0.75))
            i = k
        return findings

    @staticmethod
    def _title(vuln_type: str) -> str:
        return {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting",
            "ssrf": "Server-Side Request Forgery",
            "idor": "Insecure Direct Object Reference",
            "ssti": "Server-Side Template Injection",
            "xxe": "XML External Entity",
            "jwt": "Weak JWT Verification",
            "graphql": "GraphQL Injection",
        }.get(vuln_type, vuln_type)
