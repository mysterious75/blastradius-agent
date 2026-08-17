"""MITRE ATT&CK mapping for findings.

Loads the CWE -> ATT&CK technique table (``cwe_to_attack.yaml`` at the repo
root) and resolves techniques for findings by CWE, falling back to a
vuln-type keyword map when the finding carries no CWE.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_YAML = Path(__file__).resolve().parent.parent.parent / "cwe_to_attack.yaml"

# vuln_type -> CWE fallback for findings without a cwe field (mirrors the
# cwe values in blastradius/hunter/scanner.py VULN_META).
VULN_TYPE_TO_CWE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "ssti": "CWE-1336",
    "xxe": "CWE-611",
    "jwt": "CWE-347",
    "graphql": "CWE-943",
    "secret": "CWE-798",
    "secret_history": "CWE-798",
    "deserialization": "CWE-502",
    "cmd_injection": "CWE-78",
    "traversal": "CWE-22",
    "crlf": "CWE-93",
    "auth_bypass": "CWE-287",
    "nosqli": "CWE-943",
    "proto_pollution": "CWE-1321",
    "ci_injection": "CWE-94",
}

_cache: Optional[Dict[str, Dict[str, str]]] = None


def _finding_get(finding: Any, name: str, default: Any = None) -> Any:
    """Read an attribute or dict key from a finding-like object."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def load_cwe_to_attack(path: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    """Load the CWE -> ATT&CK table as ``{cwe: {id, name}}``.

    ``path`` defaults to ``cwe_to_attack.yaml`` at the repository root.
    Returns an empty dict when the file is missing or unparseable (never
    raises — mapping is best-effort decoration).
    """
    import yaml

    src = Path(path) if path else _DEFAULT_YAML
    try:
        data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    mapping: Dict[str, Dict[str, str]] = {}
    for cwe, meta in data.items():
        if not isinstance(meta, dict):
            continue
        tech_id = meta.get("id")
        if not tech_id:
            continue
        mapping[str(cwe).strip().upper()] = {
            "id": str(tech_id).strip(),
            "name": str(meta.get("name", "")).strip(),
        }
    return mapping


def _mapping() -> Dict[str, Dict[str, str]]:
    global _cache
    if _cache is None:
        _cache = load_cwe_to_attack()
    return _cache


def _normalize_cwe(cwe: Any) -> Optional[str]:
    if cwe is None:
        return None
    cwe = str(cwe).strip()
    if not cwe:
        return None
    if not cwe.upper().startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return cwe.upper()


def attack_for(finding: Any) -> List[Dict[str, str]]:
    """Resolve ATT&CK techniques for a finding (dict or object).

    Primary lookup is the finding's ``cwe``; when absent or unmapped, the
    finding's ``vuln_type`` is mapped to its canonical CWE and retried.
    Returns ``[]`` when nothing resolves (never raises).
    """
    mapping = _mapping()
    cwe = _normalize_cwe(_finding_get(finding, "cwe"))
    if cwe and cwe in mapping:
        return [dict(mapping[cwe])]

    vuln_type = _finding_get(finding, "vuln_type")
    if vuln_type:
        fallback_cwe = VULN_TYPE_TO_CWE.get(str(vuln_type).strip().lower())
        if fallback_cwe and fallback_cwe in mapping:
            return [dict(mapping[fallback_cwe])]
    return []
