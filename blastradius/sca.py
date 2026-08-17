"""Dependency / SCA scanning via the OSV vulnerability API.

Parses common lockfiles (best-effort), queries https://api.osv.dev/v1/querybatch
for known vulnerabilities, caches results in SQLite (7-day TTL) and provides a
severity summary. Network access is opt-in (the CLI ``--online`` flag) —
offline runs use only the cache and never crash when the OSV API is unreachable.
"""

import json
import re
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

try:  # Python >= 3.11 ships tomllib in the stdlib
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

from blastradius.db.database import SQLiteDB

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
USER_AGENT = "BlastRadius-SCA/1.0"
CACHE_TTL_DAYS = 7
_BATCH_SIZE = 200

_SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")

# Set to False when the OSV API could not be reached (flags offline runs).
network_available = True


# ---------------------------------------------------------------------------
# Lockfile parsing (best-effort; unknown/broken formats are skipped)
# ---------------------------------------------------------------------------


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _json_load(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _load_toml(path: Path):
    if tomllib is None:
        return None
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return None


def _parse_requirements(path: Path) -> List[dict]:
    text = _read_text(path)
    if text is None:
        return []
    packages = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e", "-r", "-c", "--")):
            continue
        name, _, version = line.partition("==")
        if not version:
            continue
        name = name.split("[", 1)[0].strip()
        if not name:
            continue
        version = re.split(r"[;\s]", version)[0].strip().strip("'\"")
        if version:
            packages.append({"ecosystem": "PyPI", "name": name, "version": version})
    return packages


def _parse_pipfile_lock(path: Path) -> List[dict]:
    data = _json_load(path)
    if not isinstance(data, dict):
        return []
    packages = []
    for section in ("default", "develop"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, info in entries.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "").lstrip("=<>~!^")
            if version:
                packages.append({"ecosystem": "PyPI", "name": name, "version": version})
    return packages


def _parse_poetry_lock(path: Path) -> List[dict]:
    data = _load_toml(path)
    if not isinstance(data, dict):
        return []
    packages = []
    for pkg in data.get("package") or []:
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            packages.append({"ecosystem": "PyPI", "name": name, "version": str(version)})
    return packages


def _parse_package_lock(path: Path) -> List[dict]:
    data = _json_load(path)
    if not isinstance(data, dict):
        return []
    packages = []
    for section in ("dependencies", "packages"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for key, info in entries.items():
            if not key:
                continue
            if key.startswith("node_modules/"):
                name = key.split("node_modules/")[-1]
            else:
                name = key
            version = info.get("version") if isinstance(info, dict) else info
            if version:
                packages.append({"ecosystem": "npm", "name": name, "version": str(version)})
    return packages


def _parse_go_mod(path: Path) -> List[dict]:
    text = _read_text(path)
    if text is None:
        return []
    packages = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if line == ")":
            in_block = False
            continue
        if in_block or line.startswith("require "):
            body = line[len("require ") :].strip() if line.startswith("require ") else line
            parts = body.split()
            if len(parts) >= 2 and parts[1] != "(":
                packages.append({"ecosystem": "Go", "name": parts[0], "version": parts[1]})
    return packages


def _parse_gemfile_lock(path: Path) -> List[dict]:
    text = _read_text(path)
    if text is None:
        return []
    packages = []
    for line in text.splitlines():
        match = re.match(r"^ {4}[A-Za-z0-9_.-]+ \(([^)]+)\)$", line)
        if not match:
            continue
        version = match.group(1).strip().split()[0]
        if not version or version.startswith(("=", ">", "<", "~", "!")):
            continue
        name = line.strip().split(" ", 1)[0]
        packages.append({"ecosystem": "RubyGems", "name": name, "version": version})
    return packages


def _parse_cargo_lock(path: Path) -> List[dict]:
    data = _load_toml(path)
    if not isinstance(data, dict):
        return []
    packages = []
    for pkg in data.get("package") or []:
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            packages.append({"ecosystem": "crates.io", "name": name, "version": str(version)})
    return packages


def _parse_composer_lock(path: Path) -> List[dict]:
    data = _json_load(path)
    if not isinstance(data, dict):
        return []
    packages = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict):
                continue
            name, version = pkg.get("name"), pkg.get("version")
            if not name or not version:
                continue
            version = str(version)
            if version.startswith("v") and version[1:2].isdigit():
                version = version[1:]
            packages.append({"ecosystem": "Packagist", "name": name, "version": version})
    return packages


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": _parse_poetry_lock,
    "package-lock.json": _parse_package_lock,
    "go.mod": _parse_go_mod,
    "Gemfile.lock": _parse_gemfile_lock,
    "Cargo.lock": _parse_cargo_lock,
    "composer.lock": _parse_composer_lock,
}


def parse_lockfiles(repo_path) -> List[dict]:
    """Parse supported lockfiles under ``repo_path`` (best-effort).

    Returns a list of ``{"ecosystem", "name", "version"}`` records. Unknown or
    malformed formats are silently skipped.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return []
    packages = []
    for fname, parser in _PARSERS.items():
        path = repo / fname
        if not path.is_file():
            continue
        try:
            packages.extend(parser(path))
        except Exception:
            continue
    return packages


# ---------------------------------------------------------------------------
# OSV querying (with a SQLite offline cache, 7-day TTL)
# ---------------------------------------------------------------------------


def _cache_key(pkg: dict) -> str:
    return f"{pkg.get('ecosystem', '')}|{pkg.get('name', '')}|{pkg.get('version', '')}"


def _version_key(version: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", version) or ["0"])


def _extract_advisories(vulns: List[dict]) -> List[dict]:
    """Normalise raw OSV vuln records into our advisory shape."""
    advisories = []
    for vuln in vulns or []:
        fixed_versions = []
        for rng in vuln.get("ranges") or []:
            for event in rng.get("events") or []:
                # OSV events look like {"fixed": "3.0.1"} — a "type" key is not
                # present in API responses, only the presence of the key.
                if event.get("type") == "fixed" or event.get("fixed"):
                    fixed_versions.append(event["fixed"])
        fixed = max(fixed_versions, key=_version_key) if fixed_versions else None
        db_specific = vuln.get("database_specific") or {}
        advisories.append(
            {
                "id": vuln.get("id"),
                "aliases": vuln.get("aliases") or [],
                "severity": db_specific.get("severity") or "UNKNOWN",
                "summary": vuln.get("summary"),
                "fixed": fixed,
            }
        )
    return advisories


def _osv_query_batch(packages: List[dict], timeout: int) -> List[dict]:
    queries = [
        {
            "package": {"ecosystem": pkg["ecosystem"], "name": pkg["name"]},
            "version": pkg["version"],
        }
        for pkg in packages
    ]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("results") or []


def query_osv(packages: List[dict], timeout: int = 30, online: bool = True) -> List[dict]:
    """Query OSV for ``packages`` (``{"ecosystem", "name", "version"}`` records).

    Returns a list of ``{"package": {...}, "advisories": [...]}`` in the same
    order as the input. Results are cached in SQLite (7-day TTL). When the
    network fails and the cache is empty this returns ``[]`` and sets the
    module-level ``network_available`` flag to False.
    """
    global network_available
    network_available = True
    if not packages:
        return []

    db = None
    try:
        db = SQLiteDB()
    except Exception:
        pass

    resolved = {}
    misses = []
    for pkg in packages:
        key = _cache_key(pkg)
        if db is not None:
            try:
                hit = db.get_sca(key, ttl_days=CACHE_TTL_DAYS)
            except Exception:
                hit = None
            if hit is not None:
                resolved[key] = {"package": pkg, "advisories": hit}
                continue
        misses.append(pkg)

    if misses and online:
        try:
            for start in range(0, len(misses), _BATCH_SIZE):
                batch = misses[start : start + _BATCH_SIZE]
                data = _osv_query_batch(batch, timeout=timeout)
                for idx, pkg in enumerate(batch):
                    vulns = data[idx].get("vulns", []) if idx < len(data) else []
                    advisories = _extract_advisories(vulns)
                    key = _cache_key(pkg)
                    resolved[key] = {"package": pkg, "advisories": advisories}
                    if db is not None:
                        try:
                            db.save_sca(key, advisories)
                        except Exception:
                            pass
        except Exception:
            network_available = False

    if not network_available and not resolved:
        return []

    results = []
    for pkg in packages:
        entry = resolved.get(_cache_key(pkg))
        if entry is None:
            entry = {"package": pkg, "advisories": []}
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------


def summarize(results: List[dict]) -> Dict[str, int]:
    """Count advisories by severity across ``results``."""
    counts = {sev: 0 for sev in _SEVERITIES}
    for entry in results:
        for advisory in entry.get("advisories", []):
            severity = str(advisory.get("severity") or "UNKNOWN").upper()
            if severity not in counts:
                severity = "UNKNOWN"
            counts[severity] += 1
    return counts
