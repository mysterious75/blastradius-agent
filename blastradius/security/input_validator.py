"""Input validation & hardening for external-facing entry points.

Validates:
- GitHub repo URLs (no non-GitHub hosts, no private/loopback IPs, no path
  traversal).
- Target code snippets (50KB cap, prompt-injection pattern blocking).
- Local repo paths (must resolve inside allowed directories only).
"""

import ipaddress
import os
import re
import tempfile
import urllib.parse
from pathlib import Path
from typing import List

MAX_TARGET_CODE_BYTES = 50 * 1024  # 50 KB

# Prompt-injection markers (case-insensitive) that must never reach an LLM.
_INJECTION_PATTERNS = [
    r"ignore\s+(all|any|the)?\s*(previous|prior|above|earlier)\s*(instructions?|prompts?|messages?)",
    r"ignore\s+(your\s+)?(system\s+)?prompt",
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above|earlier)?\s*instructions?",
    r"override\s+(your\s+|the\s+)?(system\s+)?(instructions?|prompt)",
    r"you\s+are\s+now\s+(a|an)?",
    r"pretend\s+you\s+are\s+",
    r"new\s+system\s+prompt",
    r"do\s+not\s+follow\s+(your|the)\s+(previous\s+)?instructions?",
    r"jailbreak",
]

_GITHUB_RE = re.compile(r"^https?://(www\.)?github\.com/", re.I)
_OWNER_REPO_RE = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")

_PRIVATE_HOSTS = ("localhost", "0.0.0.0", "::1")


# ---------------------------------------------------------------------------
# GitHub URLs
# ---------------------------------------------------------------------------


def _host_is_private(host: str) -> bool:
    """True for loopback/private/link-local/reserved addresses or local names."""
    host = host.lower()
    if host in _PRIVATE_HOSTS or host.endswith((".local", ".internal", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast
    )


def validate_github_url(url: str) -> str:
    """Validate a GitHub repo URL and return it normalized to https://github.com/owner/repo.

    Rejects non-GitHub hosts, private/loopback addresses, URLs with
    credentials, and path-traversal segments. Raises ValueError on invalid
    input.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Not a GitHub repo URL: empty")
    try:
        parsed = urllib.parse.urlsplit(url.strip())
    except ValueError as exc:
        raise ValueError(f"Not a GitHub repo URL: {url}") from exc

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"Not a GitHub repo URL: {url}")
    if parsed.username or parsed.password:
        raise ValueError(f"Not a GitHub repo URL (credentials blocked): {url}")

    host = parsed.hostname.lower()
    if _host_is_private(host):
        raise ValueError(f"Not a GitHub repo URL (private address blocked): {url}")
    if host not in ("github.com", "www.github.com"):
        raise ValueError(f"Not a GitHub repo URL: {url}")

    path = parsed.path
    if ".." in path.split("/"):
        raise ValueError(f"Not a GitHub repo URL (path traversal): {url}")
    m = _OWNER_REPO_RE.match(path)
    if not m:
        raise ValueError(f"Not a GitHub repo URL: {url}")

    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}"


# ---------------------------------------------------------------------------
# Target code
# ---------------------------------------------------------------------------


def validate_target_code(code: str) -> str:
    """Validate code before it reaches an LLM or the sandbox.

    Enforces a 50KB cap and blocks prompt-injection patterns (including those
    hidden in comments). Returns the code unchanged; raises ValueError.
    """
    if not isinstance(code, str):
        raise ValueError("target code must be a string")
    size = len(code.encode("utf-8"))
    if size > MAX_TARGET_CODE_BYTES:
        raise ValueError(
            f"target code exceeds {MAX_TARGET_CODE_BYTES // 1024}KB limit ({size} bytes)"
        )
    lowered = code.lower()
    for pattern in _INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            raise ValueError("target code contains prompt-injection pattern")
    return code


# ---------------------------------------------------------------------------
# Local repo paths
# ---------------------------------------------------------------------------


def allowed_repo_roots() -> List[Path]:
    """Allowed roots for local repo paths (env BLASTRADIUS_ALLOWED_ROOTS,
    defaulting to the system temp dir + the current working directory)."""
    raw = os.getenv("BLASTRADIUS_ALLOWED_ROOTS", "").strip()
    if raw:
        roots = [Path(p).resolve() for p in raw.split(os.pathsep) if p.strip()]
        if roots:
            return roots
    return [Path(tempfile.gettempdir()).resolve(), Path.cwd().resolve()]


def validate_repo_path(path: str) -> str:
    """Validate that a local repo path exists inside an allowed directory.

    Returns the resolved path; raises ValueError otherwise.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("repo path must be a non-empty string")
    resolved = Path(path).resolve()
    roots = allowed_repo_roots()
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise ValueError(f"repo path {path} is outside allowed directories")
    if not resolved.is_dir():
        raise ValueError(f"repo path does not exist: {path}")
    return str(resolved)
