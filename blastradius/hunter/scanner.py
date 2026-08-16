"""CVEHunter — clone a repo and statically scan its source files (Phase 3).

Prometheus's SQLi/XSS/SSRF scanners are URL scanners: they require a running
target, so local files are scanned with static sink/source rules that mirror
those three detections. Every candidate finding is additionally run through
Prometheus's AdversarialValidator (the real prometheus component) to get a
false-positive verdict, and exploitability is proven in the sandbox before a
disclosure report is written (see cli.py / disclosure.py).
"""

import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from blastradius.prometheus_bootstrap import ensure_prometheus_importable
from blastradius.security.input_validator import validate_github_url, validate_repo_path

# ---------------------------------------------------------------------------
# Static analysis rules (file-level equivalents of the URL scanners)
# ---------------------------------------------------------------------------

FILE_EXTENSIONS = (
    "*.py",
    "*.js",
    "*.php",
    "*.ts",
    "*.tsx",
    "*.rb",
    "*.java",
    "*.go",
    "*.rs",
    "*.erb",
    "*.jsx",
    "*.yml",
    "*.yaml",
)

# Paths/dirs that are never scanned (vendored code, build artifacts, migrations,
# and test code — findings in tests are never payable and drown the signal)
SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    "vendor",
    "migrations",
    "tests",
    "spec",
    "buildtest",
    "__tests__",
    "testdata",
    "test",
    "wpt",  # bare test dirs (internal/test) and Web Platform Tests harness
    "internal",  # non-public plumbing (binding wrappers, compat internals) — not external attack surface
}

# Extension -> language key used by the comment/docstring skipping logic
_LANG_OF = {
    ".py": "py",
    ".js": "js",
    ".php": "php",
    ".ts": "ts",
    ".tsx": "tsx",
    ".rb": "rb",
    ".erb": "erb",
    ".java": "java",
    ".go": "go",
    ".rs": "rs",
    ".jsx": "jsx",
}

# Untrusted input sources (request data, query params, form fields...)
SOURCES = [
    r"request\.(?:args|form|values|get_json|query_params|cookies|headers)\b",
    r"req\.(?:query|body|params|headers)\b",
    r"\$_GET|\$_POST|\$_REQUEST",
    r"getParameter\(",
    r"\binput\(",
    r"params\[",  # Rails: params is user input (a source, never a sink by itself)
    r"searchParams\.get\(",
    r"ctx\.query\b",
    r"context\.(?:request|args)\b",
    r"window\.location",
]

# SQL keywords as keyword+context pairs — a bare SELECT/DELETE/update method
# name (axios.delete, call('delete', ...), minified code) is not SQL.
_SQL_KEYWORDS = (
    r"SELECT[^;]{0,200}FROM|INSERT\s+INTO|UPDATE[^;]{0,200}SET|"
    r"DELETE\s+FROM|DELETE\s+INTO|DROP\s+TABLE|CREATE\s+TABLE|"
    r"ALTER\s+TABLE|UNION\s+(?:ALL\s+)?SELECT"
)
# String literal concatenated with a variable. f-strings and plain literals
# are intentionally NOT flagged (too many false positives).
_SQL_CONCAT = [
    r"['\"][^'\"]{0,200}['\"]\s*\+\s*[^\s'\"+=]",
]

_XSS_SINKS = [
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\bdocument\.write\(",
    r"\bdocument\.writeln\(",
    r"\bdangerouslySetInnerHTML\b",
    r"\bv-html\b",
    r"\brender_template_string\(",
    r"\binsertAdjacentHTML\(",
    r"\.html\(",
    r"\beval\(",
]
# echo/print reach the HTTP response only in PHP — elsewhere they are stdout
# (Go/Ruby/shell echo lines were a huge false-positive class on real repos)
_PHP_XSS_SINKS = [r"\becho\b", r"\bprint\s*\("]
_XSS_SAFE = [
    r"htmlspecialchars",
    r"html\.escape",
    r"\bescape\(",
    r"sanitize",
    r"purify",
    r"escapejs",
    r"DOMPurify",
    r"markupsafe",
    r"escape_html",
    r"html_escape",
    r"escapeHtml",
    r"htmlEscape",
    r"HTMLEscape",
    r"EscapeString",
    r"escapeJavaScript",
    # i18n helpers (static translation output) and self-referential version eval
    r"->t\(|gettext\b|__(?:\()|_e\(|trans\(|json_encode\(",
    r"__version_info__\s*=",
]

_SSRF_SINKS = [
    r"requests\.(?:get|post|put|delete|request|head)\(",
    r"urllib\.request\b",
    r"urlopen\(",
    r"(?<![.>])\bfetch\(",
    r"http\.(?:get|request)\(",
    r"axios\.",
    r"\bgot\(",
    r"\bcurl\(",
    r"httpx\.",
    r"aiohttp\.",
    r"(?<![.>])\brequest\(",
]
# Same-origin URL builders, explicit browser-side fetch, config-marked
# endpoints (webhook/response URLs set by admins or third-party services), and
# Fetcher-wrapper plumbing (binding -> internal service) are NOT
# attacker-controlled server-side fetches.
_SSRF_SAFE = [
    r"generateUrl|generateOcsUrl",  # same-origin builders (Nextcloud)
    r"window\.fetch",  # explicit browser-side fetch
    r"webhook_url|response_url|slack_api_http",  # config-driven endpoints
    r"fetcher\.fetch",  # binding/Fetcher wrapper plumbing
    # Worker fetch-handler signature: fetch(req, env, ctx) — a definition, not a call
    r"fetch\(\s*\w+\s*:?[^,)]*,\s*\w+\s*:?[^,)]*,\s*\w+\s*:?[^,)]*\)",
    # function definitions named request/fetch
    r"function\s+(?:request|fetch)\s*\(",
]

# Language-specific XSS sinks (Ruby/Java/Go/Rust/ERB). params[ is a SOURCE,
# not a sink — it only matters when it flows into one of the sinks below.
_LANG_XSS_SINKS = {
    "rb": [r"render\s+inline:", r"\braw\s*\(", r"\.html_safe\b"],
    "erb": [r"<%=\s*[^%]*(?:params|request)\b"],
    "java": [r"getParameter\(|\.write\s*\("],
    "go": [r"fmt\.Fprintf\s*\([^)]*r\.FormValue\("],
    "rs": [r"format!\s*\([^)]*(?:request|query|param|input|args)"],
}
# Source keywords that carry untrusted data inside a sink line
_LANG_SOURCE_KEYWORDS = (
    r"\b(?:params|request|query|input|data|body|getParameter|FormValue|args|user_input)\b"
)

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
    "secret": {
        "severity": "HIGH",
        "cvss": 8.0,
        "cwe": "CWE-798",
        "description": (
            "Hard-coded credential: a high-signal API key or token is committed "
            "to the repository. Detection only — never validate or use the key."
        ),
        "remediation": (
            "Rotate the credential, remove it from history, and load secrets "
            "from environment variables or a secret manager."
        ),
    },
    "deserialization": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-502",
        "description": (
            "Insecure deserialization: untrusted input reaches a deserializer "
            "(pickle/yaml/Marshal/unserialize/readObject), which can execute "
            "attacker-controlled code (RCE) or corrupt data."
        ),
        "remediation": (
            "Never deserialize untrusted input. Use safe loaders (yaml.safe_load, "
            "SafeLoader), signed formats (JWT/msgpack), or allowlist-restricted "
            "unpicklers; treat any user-controlled bytes as code."
        ),
    },
    "cmd_injection": {
        "severity": "CRITICAL",
        "cvss": 9.8,
        "cwe": "CWE-78",
        "description": (
            "Command/code injection: user-controlled input reaches an OS command "
            "or eval sink (os.system, subprocess shell=True, exec/eval, "
            "shell_exec, Runtime.exec), allowing attacker code execution."
        ),
        "remediation": (
            "Never pass user input to a shell. Use list-form subprocess calls "
            "without shell=True, strict allowlists, and treat eval/exec as sinks."
        ),
    },
    "traversal": {
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-22",
        "description": (
            "Path traversal: user-controlled input flows into a file path "
            "operation (open/read/join/unlink), allowing arbitrary file "
            "read/write/delete outside the intended directory."
        ),
        "remediation": (
            "Resolve paths with os.path.abspath and verify the result stays "
            "inside a known root (or use a framework's safe file APIs)."
        ),
    },
    "crlf": {
        "severity": "MEDIUM",
        "cvss": 5.0,
        "cwe": "CWE-93",
        "description": (
            "CRLF injection: user-controlled input with newline characters "
            "reaches an HTTP header or email field, allowing header "
            "injection / response splitting / SMTP command injection."
        ),
        "remediation": (
            "Strip or encode CR/LF from user input before it reaches headers "
            "or email fields; validate email addresses and header values."
        ),
    },
    "auth_bypass": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-287",
        "description": (
            "Authentication bypass: authorization is decided by client-"
            "controlled values (role/admin params, spoofable headers like "
            "X-Forwarded-For, presence-only token checks) or hardcoded "
            "credentials, letting attackers reach privileged functions."
        ),
        "remediation": (
            "Derive identity and privileges from a server-side session only; "
            "never trust client-supplied roles/headers; enforce an "
            "authorization check (login_required + ownership) on every route."
        ),
    },
    "nosqli": {
        "severity": "HIGH",
        "cvss": 8.1,
        "cwe": "CWE-943",
        "description": (
            "NoSQL injection: user-controlled input is interpolated into a "
            "MongoDB/PyMongo/Mongoose query (find/findOne filters, $where, "
            "$regex/$gt/$ne operator injection), allowing authentication "
            "bypass or unauthorized data access."
        ),
        "remediation": (
            "Never concatenate user input into NoSQL queries. Validate and "
            "type-check input (e.g. ObjectId wrapping, schema validation) and "
            "avoid $where and operator-injection filters built from raw input."
        ),
    },
    "proto_pollution": {
        "severity": "HIGH",
        "cvss": 7.5,
        "cwe": "CWE-1321",
        "description": (
            "Prototype pollution: user-controlled input reaches a prototype "
            "assignment (__proto__ / constructor.prototype / Object.prototype) "
            "or a recursive-merge utility (lodash _.merge), allowing attackers "
            "to inject properties onto Object.prototype and alter application "
            "behavior (DoS, XSS, or RCE depending on the sink)."
        ),
        "remediation": (
            "Reject '__proto__', 'constructor', and 'prototype' keys from user "
            "input, use Object.freeze / structuredClone, and sanitize keys "
            "inside recursive merge functions."
        ),
    },
    "ci_injection": {
        "severity": "HIGH",
        "cvss": 8.8,
        "cwe": "CWE-94",
        "description": (
            "GitHub Actions CI injection: a pull_request_target workflow "
            "checks out the untrusted PR head and executes it (run step or "
            "github.event.pull_request.head.sha) with repository secrets — "
            "the pwn-request / DuckDuckGo RCE pattern."
        ),
        "remediation": (
            "Never check out or execute pull-request code in pull_request_target "
            "workflows; trigger on pull_request (trusted base) or pin the base "
            "ref and gate PR code behind an approved reviewer with "
            "least-privilege tokens."
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
        re.search(r"\(\s*[A-Za-z_$][\w$]*", stripped)  # sink(<var>
        or re.search(r"=\s*[A-Za-z_$][\w$]*", stripped)  # sink = <var>
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
    if lang in ("js", "ts", "tsx", "jsx", "java", "go", "rs", "php", "rb") and stripped.startswith(
        "//"
    ):
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


def _score_xss(line: str, has_source: bool, lang: str = "") -> float:
    if any(re.search(p, line, re.I) for p in _XSS_SAFE):
        return 0.0
    sinks = _XSS_SINKS + (_PHP_XSS_SINKS if lang == "php" else [])
    if not any(re.search(p, line, re.I) for p in sinks):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.95 if has_source else 0.75


def _score_ssrf(line: str, has_source: bool) -> float:
    if not any(re.search(p, line) for p in _SSRF_SINKS):
        return 0.0
    if any(re.search(p, line, re.I) for p in _SSRF_SAFE):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.9 if has_source else 0.7


def _score_ssti(line: str, has_source: bool, lang: str = "") -> float:
    if re.search(r"render_template_string\s*\(", line):
        if _line_references_variable(line):
            return 0.9 if has_source else 0.8
        return 0.0
    # bare Template( is only an SSTI signal in Python — `new Template(...)` in
    # PHP/etc. is a class constructor, not template evaluation
    template_sinks = r"(?:jinja2\.Template|Environment\s*\(\).*from_string"
    if lang == "py":
        template_sinks += r"|\bTemplate\s*\("
    template_sinks += r")"
    if re.search(template_sinks, line):
        if _line_references_variable(line):
            return 0.8 if has_source else 0.7
    return 0.0


def _score_xxe(line: str, has_source: bool, has_defusedxml: bool) -> float:
    if has_defusedxml:
        return 0.0
    if re.search(
        r"(?:xml\.etree\.ElementTree|lxml\.etree|\betree\b|\bET\b)\.(?:parse|fromstring|parseString|XML|iterparse)\s*\(",
        line,
        re.I,
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
    if re.search(_SQL_KEYWORDS, line, re.I) and any(re.search(p, line) for p in _SQL_CONCAT):
        return 0.8 if has_source else 0.7
    return 0.0


# Hard-coded credentials (detection only — never validate or use a found key)
_SECRET_PATTERNS = [
    r"\bAIza[0-9A-Za-z\-_]{35}\b",
    r"\bsk-[A-Za-z0-9]{20,}\b",
    r"\bghp_[A-Za-z0-9]{36}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    r"\bsk_live_[A-Za-z0-9]{20,}\b",
]
_SECRET_PLACEHOLDER = re.compile(
    r"example|your-|your_|xxxx|placeholder|changeme|sample|demo|<[a-z_]+>", re.I
)


def _score_secret(line: str, has_source: bool) -> float:
    if _SECRET_PLACEHOLDER.search(line):
        return 0.0
    if any(re.search(p, line) for p in _SECRET_PATTERNS):
        return 0.95
    return 0.0


# Insecure deserialization: untrusted input reaching a deserializer
_DESERIALIZATION_SINKS = [
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
_DESERIALIZATION_SAFE = [
    r"safe_load",  # yaml.safe_load / json-compatible safe loaders
    r"SafeLoader|CSafeLoader|FullLoader",
    r"yaml\.load\s*\([^,)]*,\s*Loader\s*=",
    r"restricted_unpickler|find_class\s*=|permitted_classes",
    r"json\.loads?\s*\(|json\.parse\s*\(|SimpleJSON",
    r"Marshal\.dump\b|pickle\.dump\b|dill\.dump\b",  # writing, not reading
]


def _score_deserialization(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _DESERIALIZATION_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _DESERIALIZATION_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.9 if has_source else 0.75


# Command / code injection: user input reaching an OS command or eval sink.
# `exec(`/`eval(` are excluded after a dot so JS regex `.exec(` and object
# methods are not false positives; `window.eval(` stays flagged via \beval\b.
_CMD_INJECTION_SINKS = [
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bos\.spawn\s*\(",
    r"subprocess\.(?:run|call|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True",
    r"(?<![.\w])exec\s*\(",
    r"\beval\s*\(",
    r"\bexecfile\s*\(",
    r"\bexecSync\s*\(",
    r"child_process\.(?:exec|execSync|spawn)\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpassthru\s*\(",
    r"\bsystem\s*\(",
    r"\bpopen\s*\(",
    r"Runtime\.getRuntime\(\).*\.exec\s*\(",
    r"\bProcessBuilder\s*\(",
    r"\bjava\.lang\.Runtime\b.*\bexec\b",
]
_CMD_INJECTION_SAFE = [
    r"shlex\.quote",
    r"shell\s*=\s*False",
    r"escapeShellArg|escapeshellarg|escapeshellcmd",
    r"shellescape|shell-escape",
    r"validate_command|allowlist",
    r"subprocess\.(?:run|call|Popen)\s*\(\s*\[",  # list-form, no shell
]


def _score_cmd_injection(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _CMD_INJECTION_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _CMD_INJECTION_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.9 if has_source else 0.75


# NoSQL injection: user input interpolated into a MongoDB/PyMongo/Mongoose
# query. `.find(?:One|_one)?` covers both Mongoose's findOne and PyMongo's
# find_one; operator injection ($where/$regex/$gt/$ne) and query dicts built
# straight from request/req/body values are the canonical Rocket.Chat pattern.
_NOSQLI_SINKS = [
    r"\.find(?:One|_one)?\s*\([^)]*(?:request\.|req\.|ctx\.|body|params|data)",
    r"""\.find(?:One|_one)?\s*\([^)]*\+\s*[^\s'\"]""",
    r"\$where\s*:\s*[^,})]+(?:request|req|body|params|user|token|input)",
    r"query\s*=\s*\{[^}]*request\.|query\s*=\s*\{[^}]*req\.|filter\s*=\s*\{[^}]*request\.",
    r"(?:user|username|password|email|token)\s*:\s*(?:request\.|req\.|body\.|ctx\.)",
    r"\$(?:gt|ne|eq|regex|where)\s*:\s*(?:request\.|req\.|body\.)",
]
_NOSQLI_SAFE = [
    r"escape|sanitize|validate|allowlist|parameterized",
    r"ObjectId\s*\('\s*[A-Za-z_$][\w$]*",  # ObjectId(...)-wrapped ids are pre-validated
]


def _score_nosqli(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _NOSQLI_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _NOSQLI_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.85 if has_source else 0.75


# Prototype pollution: user input reaching a prototype assignment or a
# recursive-merge utility (lodash _.merge with attacker-controlled data).
_PROTO_POLLUTION_SINKS = [
    r"__proto__",
    r"constructor\.prototype",
    r"Object\.prototype",
    r"\.merge\s*\([^)]*(?:user|body|params|req|input|data)",
    r"merge\s*=\s*\(.*\)\s*=>",
]
_PROTO_POLLUTION_SAFE = [
    r"hasOwnProperty\s*\(\s*['\"]__proto__",
    r"hasOwnProperty\s*\.\s*call\s*\([^)]*['\"]__proto__",
    r"Object\.freeze",
    r"structuredClone",
]
_JS_LANGS = ("js", "ts", "tsx", "jsx")


def _score_proto_pollution(line: str, has_source: bool, lang: str = "") -> float:
    if lang not in _JS_LANGS:  # JS/TS-family only
        return 0.0
    if any(re.search(p, line, re.I) for p in _PROTO_POLLUTION_SAFE):
        return 0.0
    if not any(re.search(p, line) for p in _PROTO_POLLUTION_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.85 if has_source else 0.75


# GitHub Actions CI injection (pwn-request / DuckDuckGo RCE): a
# pull_request_target workflow checks out the untrusted PR head and executes
# it with repository secrets. Text-level check over the whole workflow file.
_CI_CHECKOUT = re.compile(r"uses\s*:\s*actions/checkout", re.I)
_CI_RUN_STEP = re.compile(r"^\s*-\s+run\s*:", re.M)


def _score_ci_yaml(text: str) -> float:
    """Score a GitHub Actions workflow (pull_request_target + checkout + execute)."""
    if "pull_request_target" not in text:
        return 0.0
    checkout = _CI_CHECKOUT.search(text)
    if not checkout:
        return 0.0
    # dangerous only when the untrusted PR head is checked out or executed
    head_sha = "github.event.pull_request.head.sha" in text
    run_after_checkout = any(m.start() > checkout.end() for m in _CI_RUN_STEP.finditer(text))
    if not (head_sha or run_after_checkout):
        return 0.0
    return 0.85


# Path traversal / arbitrary file operations with user-controlled paths.
_TRAVERSAL_SINKS = [
    r"\bopen\s*\(\s*[A-Za-z_$][\w$]*",
    r"\bopen\s*\([^)]*\b(?:file|path|filename|name)\b\s*,",
    r"\bfile_get_contents\s*\(",
    r"\bfread\s*\([^)]*,?\s*[A-Za-z_$]",
    r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(",
    r"\breadFileSync\s*\(",
    r"\b(?:send_file|FileResponse|static_file|sendfile)\s*\(",
    r"\bnew\s+File\s*\(",
    r"\bgetResourceAsStream\s*\(",
    r"\bPath\.join\s*\([^)]*[A-Za-z_$]",
    r"\bos\.path\.join\s*\([^)]*[A-Za-z_$]",
    r"\b(?:unlink|os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree)\s*\(",
    r"\bPath\s*\(\s*[A-Za-z_$][\w$]*",
]
_TRAVERSAL_SAFE = [
    r"abspath|realpath|normpath|resolve\s*\(|secure_filename",
    r"secureJoin|safe_join|normalize_path",
    r"os\.path\.(?:basename|dirname)",  # path decomposition, not resolution
    r"user\.file|file_storage",  # upload objects already validated by framework
]


def _score_traversal(line: str, has_source: bool, has_safe_paths: bool) -> float:
    if has_safe_paths:
        return 0.0
    if any(re.search(p, line, re.I) for p in _TRAVERSAL_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _TRAVERSAL_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.85 if has_source else 0.7


# CRLF / header injection: newline-capable user input reaching headers/email.
_CRLF_SINKS = [
    r"\b(?:set_header|add_header|send_header|append_header|setHeader|addHeader)\s*\(",
    r"\bHeader\s*\([^)]*[A-Za-z_$][\w$]*,",
    r"\bLocation\s*:\s*[^\"'\n]*[A-Za-z_$]",
    r"sendmail\s*\([^)]*[A-Za-z_$]",
    r"\bmsg\[\s*['\"][^'\"]*['\"]\s*\]\s*=\s*[A-Za-z_$]",
    r"\bheaders?\s*\[[^]]*\]\s*=[^=]",
    r"\.headers?\s*\.\s*set\s*\(",
]
_CRLF_SAFE = [r"quote|escape|sanitize|strip|validate|encode"]


def _score_crlf(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _CRLF_SAFE):
        return 0.0
    if not any(re.search(p, line, re.I) for p in _CRLF_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.8 if has_source else 0.7


# Authentication bypass: client-controlled privilege, spoofable headers,
# presence-only token checks, hardcoded credential compares (corpus-derived).
_AUTH_BYPASS_SINKS = [
    # client-supplied role/admin/privilege assignment or decision
    r"\b(?:role|is_admin|isadmin|admin|user_type|privilege|is_superuser|group)\s*=\s*"
    r"(?:request\.|req\.|context\.|body\[|params\[|data\[|json\[)",
    r"\bif\s+(?:request\.|req\.|context\.|body|params|data)\.?(?:args|form|values|get_json)?"
    r"\s*\.?get?\(?[^)]*['\"](?:admin|role|is_admin|is_superuser|user_type)['\"]",
    # presence-only token/auth check ("if token:" without validation)
    r"\bif\s+(?:token|auth|api_key|key|session_id|passwd)\s*:",
    # trusting spoofable headers for identity/remote address
    r"headers?\s*\[[\"'](?:X-Forwarded-For|X-Real-IP|X-Original-URL|X-Rewrite-URL|"
    r"X-Forwarded-Host|X-Forwarded-Proto)[\"']\]",
    r"(?:get_remote_addr|client_ip|remote_addr|REMOTE_ADDR)\s*=.*(?:X-Forwarded|X-Real-IP)",
    r"X-Gitlab-Workhorse-Api-Request|Workhorse\.verify_api_request",
]
# Hardcoded credential comparison — the comparison itself is the signal.
_AUTH_CRED_COMPARE = re.compile(
    r"(?:password|passwd|pass|pwd)\s*==\s*['\"](?:admin|password|1234|123456|root|test)['\"]",
    re.I,
)
_AUTH_BYPASS_SAFE = [
    r"login_required|is_authenticated|current_user|@login|@auth|@admin_required|"
    r"requires_auth|jwt\.require|verify_token|check_permission|has_access|"
    r"permission_required|roles_required|session\[|secure_session|access_control",
    r"X-Forwarded-For\s*=\s*None|if\s+X-Forwarded-For",  # documented, not trusted
]


def _score_auth_bypass(line: str, has_source: bool) -> float:
    if any(re.search(p, line, re.I) for p in _AUTH_BYPASS_SAFE):
        return 0.0
    if _AUTH_CRED_COMPARE.search(line):
        return 0.85 if has_source else 0.8
    if not any(re.search(p, line, re.I) for p in _AUTH_BYPASS_SINKS):
        return 0.0
    if not _line_references_variable(line):
        return 0.0
    return 0.85 if has_source else 0.75


# IDOR: object-id read from user input, no authorization check nearby.
# Multi-language sources (py/js/php/rb/java/go) + object-id names beyond "id".
_IDOR_NAMES = (
    r"(?:id|user_id|account_id|order_id|document_id|file_id|project_id|task_id|"
    r"object_id|customer_id|org_id|team_id|payment_id|attachment_id|message_id|"
    r"post_id|product_id|invoice_id|uuid)"
)
_IDOR_ID_SOURCES = [
    rf"request\.(?:args|form|values|get_json)\s*\([^)]*['\"]{_IDOR_NAMES}['\"]",
    rf"getParameter\(\s*['\"]{_IDOR_NAMES}['\"]",
    r"@PathVariable\s*(?:\([^)]*\)\s*)?\w*(?:Id|ID|Uuid|UUID)\b",
    rf"req\.(?:params|query|body)\.{_IDOR_NAMES}\b",
    rf"params\[[:'\"]?{_IDOR_NAMES}[:'\"]?\]",
    rf"\$_?(?:GET|POST|REQUEST)\s*\[['\"]{_IDOR_NAMES}['\"]\]",
    rf"r\.URL\.Query\(\)\.Get\(['\"]{_IDOR_NAMES}['\"]\)",
    rf"chi\.URLParam\([^)]*['\"]{_IDOR_NAMES}['\"]\)|mux\.Vars\([^)]*\)\[['\"]{_IDOR_NAMES}['\"]\]",
    r"['\"][^'\"]*<int:[^'\"]*>['\"]",
    r"request\.view_args",
    rf"\b{_IDOR_NAMES}\s*=\s*(?:request\.|req\.|context\.|r\.FormValue)",
]
# Authorization markers: auth decorators + object-level ownership checks.
_IDOR_AUTH = [
    r"@?login_required|@?authenticated|@?auth\b|requires?_(?:auth|authentication)|"
    r"is_authenticated|current_user|request\.user|req\.user|session\[|req\.session|"
    r"\$_SESSION|jwt_required|@?jwt\.require|token_required|oauth2\.require",
    r"@?permission_required|has_permission|check_permission|permission\b|@?roles_required|"
    r"require_role|can_access|authorize|authorized|@admin_required|is_admin\b",
    r"is_owner|ownership|check_owner|assert_owner|verify_owner|belongs_to|"
    r"filter\([^)]*(?:user|owner|account|org|team)[^)]*\)|\.where\([^)]*(?:user_id|owner_id)",
    r"user_id\s*==|owner_id\s*==|==\s*current_user|current_user\.(?:id|uuid|uid)\s*==",
]
_FUNC_START = {
    "py": re.compile(r"^\s*def\s+"),
    "rb": re.compile(r"^\s*def\s+"),
    "php": re.compile(r"^\s*function\s+\w+\s*\("),
    "js": re.compile(
        r"^\s*(?:function\s*\w*\s*\(|(?:async\s+)?\(\s*[\w\s,$]*\)\s*=>|"
        r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\(.*=>)"
    ),
    "ts": re.compile(
        r"^\s*(?:function\s*\w*\s*\(|(?:async\s+)?\(\s*[\w\s,$]*\)\s*=>|"
        r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\(.*=>)"
    ),
    "tsx": re.compile(
        r"^\s*(?:function\s*\w*\s*\(|(?:async\s+)?\(\s*[\w\s,$]*\)\s*=>|"
        r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\(.*=>)"
    ),
    "jsx": re.compile(
        r"^\s*(?:function\s*\w*\s*\(|(?:async\s+)?\(\s*[\w\s,$]*\)\s*=>|"
        r"(?:app|router|server)\.(?:get|post|put|delete|patch|use)\s*\(.*=>)"
    ),
    "go": re.compile(r"^\s*func\s+"),
    "java": re.compile(
        r"^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>,\[\]\s]+\([^)]*\)\s*\{?"
    ),
}
# Direct route/id signals raise IDOR confidence
_IDOR_HIGH_CONF = re.compile(
    r"getParameter|@PathVariable|<int:|view_args|req\.params|mux\.Vars|chi\.URLParam|"
    r"URL\.Query\(\)|r\.FormValue",
    re.I,
)


def _score_lang_xss(line: str, lang: str, has_source: bool) -> float:
    """Language-specific XSS sinks (Ruby/Java/Go/Rust/ERB)."""
    sinks = _LANG_XSS_SINKS.get(lang)
    if not sinks or not any(re.search(p, line, re.I) for p in sinks):
        return 0.0
    if any(re.search(p, line, re.I) for p in _XSS_SAFE):
        return 0.0
    stripped = re.sub(r"['\"][^'\"]*['\"]", " ", line)
    if not re.search(_LANG_SOURCE_KEYWORDS, stripped, re.I) and not has_source:
        return 0.0
    return 0.85 if has_source else 0.75


_SCORERS = (
    ("sqli", _score_sqli),
    ("xss", _score_xss),
    ("ssrf", _score_ssrf),
    ("ssti", _score_ssti),
    ("jwt", _score_jwt),
    ("secret", _score_secret),
    ("deserialization", _score_deserialization),
    ("cmd_injection", _score_cmd_injection),
    ("traversal", _score_traversal),
    ("crlf", _score_crlf),
    ("auth_bypass", _score_auth_bypass),
    ("nosqli", _score_nosqli),
    ("proto_pollution", _score_proto_pollution),
)


def reconstruct_target_code(finding: Finding) -> str:
    """Build a minimal reproduction of the detected pattern.

    Used to sandbox-validate the finding. The reproduction is synthetic: it
    proves the *pattern* is exploitable, not that the real file is — manual
    confirmation is required before disclosure. Never raises: unknown vuln
    types get a generic template so the pipeline always completes.
    """
    if finding.vuln_type == "sqli":
        return 'def target(user_input):\n    return "SELECT * FROM users WHERE name = \'" + user_input + "\'"\n'
    if finding.vuln_type == "xss":
        return (
            'def target(user_input):\n    return "<html><body>" + user_input + "</body></html>"\n'
        )
    if finding.vuln_type == "ssrf":
        return 'def target(user_input):\n    return "http://internal-service/fetch?url=" + user_input\n'
    if finding.vuln_type == "graphql":
        return '# GraphQL resolver\nresult = db.execute("{}".format(user_input))\n'
    if finding.vuln_type == "idor":
        return (
            "def target(user_input):\n"
            '    records = {"1": "alice-private-data", "2": "bob-private-data"}\n'
            '    return records.get(user_input, "not found")\n'
        )
    if finding.vuln_type == "jwt":
        return '# JWT\nimport jwt\ndata = jwt.decode(token, options={"verify_signature": False})\n'
    if finding.vuln_type == "xxe":
        return "# XXE\nimport xml.etree.ElementTree as ET\nET.parse(user_input)\n"
    if finding.vuln_type == "ssti":
        return "# SSTI\nfrom jinja2 import Environment\nenv = Environment()\nenv.from_string(user_input).render()\n"
    if finding.vuln_type == "deserialization":
        return "import pickle\ndef target(user_input):\n    return pickle.loads(user_input)\n"
    if finding.vuln_type == "cmd_injection":
        return "import os\ndef target(user_input):\n    os.system(user_input)\n"
    if finding.vuln_type == "traversal":
        return "def target(user_input):\n    return open(user_input).read()\n"
    if finding.vuln_type == "crlf":
        return (
            'def target(user_input):\n    return "Location: /next" + user_input + "\\r\\n\\r\\n"\n'
        )
    if finding.vuln_type == "auth_bypass":
        return 'def target(user_input):\n    role = user_input\n    return "admin_panel" if role == "admin" else "denied"\n'
    if finding.vuln_type == "nosqli":
        return (
            "def target(user_input):\n"
            "    q = {'username': user_input}\n"
            "    return 'matched' if q['username'] else 'denied'\n"
        )
    return f"# {finding.vuln_type}\nresult = process(user_input)\n"


# ---------------------------------------------------------------------------
# CVEHunter
# ---------------------------------------------------------------------------


def _load_learned_rules() -> dict:
    """Read ~/.blastradius/learned_rules.json (written by SelfImprover)."""
    try:
        path = (
            Path(os.getenv("BLASTRADIUS_HOME", str(Path.home())))
            / ".blastradius"
            / "learned_rules.json"
        )
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


class CVEHunter:
    """Clone a repo and scan its source files for vulnerability candidates."""

    def __init__(self, min_confidence: float = 0.7, clone_timeout: int = 120):
        self.min_confidence = min_confidence
        self.clone_timeout = clone_timeout
        self.files_scanned: int = 0
        self._validator = None
        # learned rules override defaults (confidence thresholds, skip
        # patterns, payload weights) — empty when nothing has been learned.
        self.learned_rules = _load_learned_rules()

    def _learned_threshold(self, vuln_type: str) -> float:
        learned = self.learned_rules.get("confidence_thresholds", {}).get(vuln_type, 0.0)
        return max(self.min_confidence, float(learned))

    @property
    def validator(self):
        """Prometheus AdversarialValidator (lazy, optional — no prometheus needed)."""
        if self._validator is None:
            try:
                ensure_prometheus_importable()
                from src.scanner.adversarial import AdversarialValidator  # noqa: E402

                self._validator = AdversarialValidator()
            except Exception:
                self._validator = False  # prometheus unavailable — use fallback
        return self._validator or None

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
                check=True,
                capture_output=True,
                text=True,
                timeout=self.clone_timeout,
            )
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"git clone failed: {exc.stderr.strip() or exc}") from exc
        return str(dest)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_repo(
        self, repo_path: str, progress=None, use_cache: Optional[bool] = None
    ) -> List[Finding]:
        """Scan every eligible file in ``repo_path`` (parallel by default).

        The path must resolve inside an allowed directory (see
        security.input_validator). Returns candidate findings with confidence
        >= ``min_confidence``, sorted by file/line. ``progress`` is an optional
        on_file_scanned(file, findings_count) callback. The content cache is
        used when BLASTRADIUS_SCAN_CACHE=1 (or ``use_cache=True``).
        """
        repo_path = validate_repo_path(repo_path)
        from blastradius.scanners.cache import ScanCache
        from blastradius.scanners.parallel import ParallelScanner

        cache = None
        if use_cache is None:
            use_cache = os.getenv("BLASTRADIUS_SCAN_CACHE", "").lower() in ("1", "true", "yes")
        if use_cache:
            cache = ScanCache()
        parallel = ParallelScanner(progress=progress, cache=cache)
        findings = parallel.scan_repo_parallel(
            repo_path, self._scan_file, list(self._iter_files(repo_path))
        )
        self.files_scanned = parallel.file_count
        findings.sort(key=lambda f: (f.file, f.line, f.vuln_type))
        return findings

    def validate(self, finding: Finding) -> str:
        """Adversarial false-positive verdict (Prometheus when available)."""
        validator = self.validator
        if validator is None:
            return "needs_manual_review"  # prometheus absent — safe default
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
        return validator.validate(pf).verdict

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _iter_files(self, repo_path: str):
        root = Path(repo_path)
        skip_patterns = self.learned_rules.get("skip_patterns", [])
        for ext in FILE_EXTENSIONS:
            for path in root.rglob(ext):
                if any(part in SKIP_DIRS or part.endswith("-test") for part in path.parts):
                    continue
                if "min." in path.name:  # minified bundles — noise, never real code
                    continue
                if (
                    path.stem.endswith("_test")
                    or path.stem.startswith("test_")
                    or path.stem.endswith(".test")
                    or path.stem.endswith(".spec")
                    or path.stem.endswith("_spec")
                ):  # *_test.go, test_*.py, *.test.js, *.spec.ts
                    continue
                if any(
                    fnmatch.fnmatch(path.name, p) or fnmatch.fnmatch(str(path), p)
                    for p in skip_patterns
                ):
                    continue
                yield path

    def _make_finding(
        self, path: Path, idx: int, lines: list, vuln_type: str, score: float
    ) -> Finding:
        meta = VULN_META[vuln_type]
        payload = lines[idx - 1].strip()
        # learned payload weights boost proven patterns (capped at 1.0)
        weights = self.learned_rules.get("payload_weights", {}).get(vuln_type, {})
        for substring, weight in weights.items():
            if substring and substring in payload:
                score = min(1.0, score * float(weight))
        return Finding(
            file=str(path),
            line=idx,
            vuln_type=vuln_type,
            payload=payload,
            confidence=round(score, 2),
            evidence=payload,
            context="\n".join(lines[max(0, idx - 2) : idx + 1]),
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
        # GitHub Actions workflow YAML — the CI-injection check is text-level
        # (whole file), not line-scored like the code scanners below.
        if path.suffix.lower() in (".yml", ".yaml") and ".github" in path.parts:
            ci_score = _score_ci_yaml(text)
            if ci_score >= self._learned_threshold("ci_injection"):
                return [self._make_finding(path, 1, text.splitlines(), "ci_injection", ci_score)]
            return []
        lines = text.splitlines()
        has_source = any(re.search(p, text, re.I) for p in SOURCES)
        has_defusedxml = "defusedxml" in text
        has_graphql = any(
            re.search(
                r"resolve_|strawberry\.field|graphene\.ObjectType|\bField\s*\(|@strawberry", line
            )
            for line in lines
        )
        lang = _LANG_OF.get(path.suffix.lower(), "py")
        has_safe_paths = any(
            re.search(p, text, re.I) for p in _TRAVERSAL_SAFE
        )  # file-level path hardening (abspath + root check) suppresses traversal
        state = {"in_docstring": False, "in_block": False}

        findings: List[Finding] = []
        for idx, line in enumerate(lines, start=1):
            if _is_skippable_line(line, lang, state):
                continue
            for vuln_type, scorer in _SCORERS:
                if vuln_type == "xss":
                    score = _score_xss(line, has_source, lang)
                elif vuln_type == "ssti":
                    score = _score_ssti(line, has_source, lang)
                elif vuln_type == "traversal":
                    score = _score_traversal(line, has_source, has_safe_paths)
                elif vuln_type == "proto_pollution":
                    score = _score_proto_pollution(line, has_source, lang)
                else:
                    score = scorer(line, has_source)
                if score < self._learned_threshold(vuln_type):
                    continue
                findings.append(self._make_finding(path, idx, lines, vuln_type, score))
            if lang == "py":
                xxe_score = _score_xxe(line, has_source, has_defusedxml)
                if xxe_score >= self._learned_threshold("xxe"):
                    findings.append(self._make_finding(path, idx, lines, "xxe", xxe_score))
            graphql_score = _score_graphql(line, has_source, has_graphql)
            if graphql_score >= self._learned_threshold("graphql"):
                findings.append(self._make_finding(path, idx, lines, "graphql", graphql_score))
            lang_score = _score_lang_xss(line, lang, has_source)
            if lang_score >= self._learned_threshold("xss"):
                findings.append(self._make_finding(path, idx, lines, "xss", lang_score))
        if lang in _FUNC_START:
            findings.extend(self._scan_idor(lines, path, lang))
        return findings

    def _scan_idor(self, lines: list, path: Path, lang: str) -> List[Finding]:
        """Function-level IDOR check: object-id from user input, no auth/ownership
        check in the function (multi-language)."""
        findings: List[Finding] = []
        n = len(lines)
        i = 0
        while i < n:
            if not _FUNC_START[lang].search(lines[i]):
                i += 1
                continue

            # collect decorators/annotations directly above the function
            j = i
            decorators = []
            while j > 0 and lines[j - 1].strip().startswith(("@", "@@")):
                decorators.insert(0, lines[j - 1])
                j -= 1

            # collect the body until the next function at the same/lower indentation
            base = len(lines[i]) - len(lines[i].lstrip())
            k = i + 1
            while k < n:
                l2 = lines[k]
                if l2.strip() and (len(l2) - len(l2.lstrip())) <= base:
                    if _FUNC_START[lang].search(l2) or (
                        lang == "java"
                        and l2.strip().startswith(("@", "public", "private", "protected"))
                    ):
                        break
                    if not l2.strip().startswith((")", "]", "}")):
                        break
                k += 1

            func_text = "\n".join(decorators + [lines[i]] + lines[i + 1 : k])
            has_id = any(re.search(p, func_text, re.I) for p in _IDOR_ID_SOURCES)
            has_auth = any(re.search(p, func_text, re.I) for p in _IDOR_AUTH)
            if has_id and not has_auth:
                confidence = 0.8 if _IDOR_HIGH_CONF.search(func_text) else 0.75
                findings.append(self._make_finding(path, i + 1, lines, "idor", confidence))
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
            "deserialization": "Insecure Deserialization",
            "cmd_injection": "Command Injection",
            "traversal": "Path Traversal",
            "crlf": "CRLF Injection",
            "auth_bypass": "Authentication Bypass",
            "nosqli": "NoSQL Injection",
            "proto_pollution": "Prototype Pollution",
            "ci_injection": "CI Injection",
        }.get(vuln_type, vuln_type)
