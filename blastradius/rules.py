"""Custom YAML rules + inline suppression + learned FP allowlists.

Three pieces plug into :class:`~blastradius.hunter.scanner.CVEHunter`:

1. ``rules/`` directory of YAML rule files (default ``<repo root>/rules``,
   override with ``BLASTRADIUS_RULES_DIR``). A rule is::

       id: demo-sink
       name: Demo sink
       description: A dangerous sink call.
       severity: HIGH
       cwe: CWE-20
       languages: [py, js]      # optional, default: all
       pattern: "super-sink\\("  # required, regex
       source_required: false   # optional: file must contain an input source
       confidence: 0.9          # optional, default 0.7

2. ``match_rules(lines, path)`` returns Finding-like dicts (``vuln_type`` is
   always ``"custom"``) for every line a rule matches, honoring the file's
   language (via suffix), ``source_required``, and learned skip patterns.

3. Suppression — ``is_suppressed(file, line, vuln_type)``:
   - inline ``blastradius:ignore`` (or ``blastradius:ignore <type>``) on the
     line or the two lines above it;
   - a global ``.blastradiusignore`` file (one ``file:line:type`` entry per
     line, ``#`` comments allowed) looked up upward from the scanned file,
     read once and cached.

4. FP feedback loop — ``add_to_allowlist(vuln_type, pattern)`` appends a
   regex to the per-type learned skip list in ``~/.blastradius/learned_rules.json``
   (the same file :mod:`blastradius.learning.improver` maintains), and
   ``match_rules`` stops emitting matches on lines that hit a learned pattern.

PyYAML is optional. When it is missing the module degrades gracefully:
``match_rules`` returns ``[]`` and no custom rules run — install it with
``pip install pyyaml`` to enable custom rules.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - environment without PyYAML
    import yaml
except Exception:  # pragma: no cover
    yaml = None

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# Extension -> language key (mirrors hunter.scanner._LANG_OF, plus YAML files)
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
    ".yml": "yaml",
    ".yaml": "yaml",
}

# File-level "has untrusted input source" check used by source_required rules
# (a subset of the SOURCES list in hunter/scanner.py).
_SOURCE_RE = re.compile(
    r"request\.(?:args|form|values|get_json|query_params|cookies|headers)\b|"
    r"req\.(?:query|body|params|headers)\b|"
    r"\$_GET|\$_POST|\$_REQUEST|"
    r"getParameter\(|\binput\(|"
    r"params\[|searchParams\.get\(|ctx\.query\b|"
    r"context\.(?:request|args)\b|window\.location",
    re.I,
)

# Inline suppression marker: `blastradius:ignore` (any type) or
# `blastradius:ignore <type>` / `blastradius:ignore:<type>`.
_IGNORE_TYPED_RE = re.compile(r"blastradius:ignore(?::|\s+)([A-Za-z0-9_]+)")

# ---------------------------------------------------------------------------
# Caches (invalidated by path + mtime so tests/edits are picked up)
# ---------------------------------------------------------------------------

_rules_cache: Dict[str, Any] = {"sig": None, "rules": []}
_lines_cache: Dict[Path, tuple] = {}
_ignore_cache: Dict[str, Any] = {"path": None, "mtime": None, "entries": []}
_learned_cache: Dict[str, Any] = {"path": None, "mtime": None, "data": {}}


def _rules_dir() -> Path:
    override = os.getenv("BLASTRADIUS_RULES_DIR")
    return Path(override) if override else DEFAULT_RULES_DIR


def _rule_files(rules_dir: Path) -> List[Path]:
    try:
        if not rules_dir.is_dir():
            return []
        return sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml"))
    except OSError:  # pragma: no cover - defensive
        return []


def _parse_rule(item: Any) -> Optional[Dict[str, Any]]:
    """Validate/normalize a raw YAML mapping into a usable rule dict."""
    if not isinstance(item, dict):
        return None
    pattern = item.get("pattern")
    if not pattern:
        return None
    try:
        compiled = re.compile(str(pattern), re.I)
    except re.error:
        return None
    languages = item.get("languages")
    if isinstance(languages, str):
        languages = [languages]
    if isinstance(languages, list):
        languages = {str(lang).strip().lower() for lang in languages if str(lang).strip()}
    else:
        languages = None
    try:
        confidence = float(item.get("confidence", 0.7))
    except (TypeError, ValueError):
        confidence = 0.7
    return {
        "id": str(item.get("id") or ""),
        "name": str(item.get("name") or item.get("id") or "custom"),
        "description": str(item.get("description") or ""),
        "severity": str(item.get("severity") or "MEDIUM"),
        "cwe": str(item.get("cwe") or ""),
        "languages": languages,
        "source_required": bool(item.get("source_required", False)),
        "confidence": min(max(confidence, 0.0), 1.0),
        "pattern": str(pattern),
        "remediation": str(item.get("remediation") or ""),
        "_re": compiled,
    }


def _load_rules() -> List[Dict[str, Any]]:
    """Load + validate every rule file; cached on (dir, mtimes)."""
    if yaml is None:
        return []
    rules_dir = _rules_dir()
    files = _rule_files(rules_dir)
    sig = [(f, f.stat().st_mtime_ns) for f in files]
    if _rules_cache["sig"] == sig:
        return _rules_cache["rules"]
    rules: List[Dict[str, Any]] = []
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            rule = _parse_rule(item)
            if rule is not None:
                rules.append(rule)
    _rules_cache.update(sig=sig, rules=rules)
    return rules


# ---------------------------------------------------------------------------
# Public API: match custom rules
# ---------------------------------------------------------------------------


def _file_has_source(lines: List[str]) -> bool:
    return bool(_SOURCE_RE.search("\n".join(lines)))


def _learned_rules_path() -> Path:
    return (
        Path(os.getenv("BLASTRADIUS_HOME", str(Path.home())))
        / ".blastradius"
        / "learned_rules.json"
    )


def _read_learned() -> Dict[str, Any]:
    path = _learned_rules_path()
    try:
        mtime = path.stat().st_mtime_ns if path.is_file() else 0
    except OSError:
        mtime = 0
    if _learned_cache["path"] == path and _learned_cache["mtime"] == mtime:
        return _learned_cache["data"]
    data: Dict[str, Any] = {}
    if mtime:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    _learned_cache.update(path=path, mtime=mtime, data=data)
    return data


def _learned_line_skips() -> Dict[str, List[str]]:
    return _read_learned().get("line_skip_patterns", {}) or {}


def _line_skipped(line: str, vuln_type: str, skips: Optional[Dict[str, List[str]]] = None) -> bool:
    """True when a learned FP allowlist regex matches this line."""
    skips = skips if skips is not None else _learned_line_skips()
    for pattern in skips.get(vuln_type, []) + skips.get("*", []):
        try:
            if re.search(pattern, line, re.I):
                return True
        except re.error:
            continue
    return False


def match_rules(lines: List[str], path) -> List[Dict[str, Any]]:
    """Apply every custom rule to ``lines`` of ``path`` (Finding-like dicts).

    Emits one dict per (rule, line) match: ``{file, line, vuln_type: "custom",
    payload, confidence, severity, cwe, description, remediation}``. Lines hit
    by a learned FP allowlist pattern are skipped. Returns ``[]`` when PyYAML
    is missing, the rules directory is absent, or nothing matches.
    """
    rules = _load_rules()
    if not rules or not lines:
        return []
    path = Path(path)
    lang = _LANG_OF.get(path.suffix.lower(), "py")
    learned_skips = _learned_line_skips()
    findings: List[Dict[str, Any]] = []
    has_source: Optional[bool] = None
    for rule in rules:
        if rule["languages"] is not None and lang not in rule["languages"]:
            continue
        compiled = rule["_re"]
        for idx, line in enumerate(lines, start=1):
            if not compiled.search(line):
                continue
            if rule["source_required"]:
                if has_source is None:
                    has_source = _file_has_source(lines)
                if not has_source:
                    continue
            if _line_skipped(line, "custom", learned_skips) or _line_skipped(
                line, rule["id"], learned_skips
            ):
                continue
            payload = line.strip()
            findings.append(
                {
                    "file": str(path),
                    "line": idx,
                    "vuln_type": "custom",
                    "payload": payload,
                    "confidence": rule["confidence"],
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "evidence": payload,
                    "context": payload,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Public API: suppression
# ---------------------------------------------------------------------------


def _marker_type(line: str) -> Optional[str]:
    """Return the vuln type a blastradius:ignore marker suppresses (or '*' for any)."""
    if "blastradius:ignore" not in line:
        return None
    m = _IGNORE_TYPED_RE.search(line)
    return m.group(1) if m else "*"


def _file_lines(path: Path) -> List[str]:
    try:
        st = path.stat()
    except OSError:
        return []
    cached = _lines_cache.get(path)
    if cached and cached[0] == st.st_mtime_ns:
        return cached[1]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    if len(_lines_cache) > 64:
        _lines_cache.clear()
    _lines_cache[path] = (st.st_mtime_ns, lines)
    return lines


def _find_ignore_file(start_dir: Path) -> Optional[Path]:
    """Walk upward from ``start_dir`` looking for .blastradiusignore."""
    d = start_dir
    for _ in range(20):  # cap upward traversal
        candidate = d / ".blastradiusignore"
        if candidate.is_file():
            return candidate
        if d.parent == d:
            break
        d = d.parent
    return None


def _parse_ignore_entry(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.rsplit(":", 2)
    if len(parts) == 1:
        return {"file": parts[0], "line": "*", "type": "*"}
    if len(parts) == 2:
        return {"file": parts[0], "line": _int_or_star(parts[1]), "type": "*"}
    return {"file": parts[0], "line": _int_or_star(parts[1]), "type": parts[2]}


def _int_or_star(value: str):
    try:
        return int(value)
    except ValueError:
        return "*"


def _entry_matches(entry: Dict[str, Any], finding_path: Path, line: int, vuln_type: str) -> bool:
    fname = str(finding_path).replace("\\", "/")
    entry_file = entry["file"].replace("\\", "/")
    file_ok = (
        entry_file == "*" or fname.endswith(entry_file) or Path(fname).name == Path(entry_file).name
    )
    line_ok = entry["line"] == "*" or entry["line"] == line
    type_ok = entry["type"] in ("*", "") or entry["type"] == vuln_type
    return file_ok and line_ok and type_ok


def _load_ignore_file(finding_path: Path) -> List[Dict[str, Any]]:
    """Read the nearest .blastradiusignore (cached by path + mtime)."""
    ignore_file = _find_ignore_file(finding_path.parent)
    if ignore_file is None:
        _ignore_cache.update(path=None, mtime=None, entries=[])
        return []
    try:
        mtime = ignore_file.stat().st_mtime_ns
    except OSError:
        mtime = 0
    if _ignore_cache["path"] == ignore_file and _ignore_cache["mtime"] == mtime:
        return _ignore_cache["entries"]
    entries: List[Dict[str, Any]] = []
    try:
        for raw in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
            entry = _parse_ignore_entry(raw)
            if entry is not None:
                entries.append(entry)
    except OSError:  # pragma: no cover - defensive
        entries = []
    _ignore_cache.update(path=ignore_file, mtime=mtime, entries=entries)
    return entries


def is_suppressed(file, line: int, vuln_type: str) -> bool:
    """True when the finding is explicitly suppressed.

    Suppression comes from an inline ``blastradius:ignore`` marker on the line
    or the two lines above it, or from a ``.blastradiusignore`` entry matching
    ``file:line:type``.
    """
    path = Path(file)
    lines = _file_lines(path)
    # 1-indexed: check the finding line and the 2 lines above it
    for i in range(max(0, line - 3), min(line, len(lines))):
        marker = _marker_type(lines[i])
        if marker is not None and (marker == "*" or marker == vuln_type):
            return True
    return any(_entry_matches(e, path, line, vuln_type) for e in _load_ignore_file(path))


# ---------------------------------------------------------------------------
# Public API: FP feedback loop
# ---------------------------------------------------------------------------


def add_to_allowlist(vuln_type: str, pattern: str) -> Dict[str, Any]:
    """Append ``pattern`` (a regex) to the learned per-type skip list.

    Reads ~/.blastradius/learned_rules.json (the file SelfImprover maintains),
    merges the pattern under ``line_skip_patterns[vuln_type]`` and the flat
    ``skip_patterns`` list, and writes it back. ``match_rules`` (and the
    scanner) stop emitting findings on lines that match a learned pattern —
    this closes the FP feedback loop.
    """
    rules = _read_learned()
    per_type = rules.setdefault("line_skip_patterns", {})
    lst = per_type.setdefault(vuln_type, [])
    if pattern not in lst:
        lst.append(pattern)
    flat = rules.setdefault("skip_patterns", [])
    if pattern not in flat:
        flat.append(pattern)
    path = _learned_rules_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rules, indent=2), encoding="utf-8")
    except OSError:  # pragma: no cover - defensive
        return rules
    _read_learned()  # refresh the cache
    return rules
