"""BlastRadius self-contained scanners — no prometheus dependency.

ScannerRegistry auto-discovers every scanner in this package; ``scan_file``
runs them all against a file's source.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional

__all__ = ["get_scanners", "get_scanner", "scan_file"]


def _discover() -> Dict[str, object]:
    scanners: Dict[str, object] = {}
    for modinfo in pkgutil.iter_modules(__path__):
        if modinfo.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{modinfo.name}")
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if isinstance(obj, type) and getattr(obj, "name", None) and hasattr(obj, "detect"):
                scanners[obj.name] = obj()
    return scanners


def get_scanners() -> Dict[str, object]:
    """All discovered scanners keyed by name (sqli, xss, ssrf, ssti, xxe)."""
    return _discover()


def get_scanner(name: str) -> Optional[object]:
    return get_scanners().get(name)


def scan_file(path, code: Optional[str] = None):
    """Run every scanner against a file; returns List[Finding]."""
    if code is None:
        try:
            code = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    findings = []
    for scanner in get_scanners().values():
        try:
            findings.extend(scanner.detect(code, path=str(path)))
        except Exception:
            continue
    findings.sort(key=lambda f: (f.file, f.line, f.vuln_type))
    return findings
