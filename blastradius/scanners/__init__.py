"""BlastRadius self-contained scanners — no prometheus dependency.

ScannerRegistry auto-discovers every scanner in this package; ``scan_file``
runs them all against a file's source.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Union

from blastradius.hunter.scanner import Finding

__all__ = ["get_scanners", "get_scanner", "scan_file"]


class Scanner(Protocol):
    name: str

    def detect(self, code: str, path: str = ...) -> List[Finding]: ...


def _discover() -> Dict[str, Scanner]:
    scanners: Dict[str, Scanner] = {}
    for modinfo in pkgutil.iter_modules(__path__):
        if modinfo.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{modinfo.name}")
        for attr_name in dir(module):
            candidate = getattr(module, attr_name)
            if not isinstance(candidate, type):
                continue
            name = getattr(candidate, "name", None)
            detect = getattr(candidate, "detect", None)
            if isinstance(name, str) and name and callable(detect):
                scanners[name] = candidate()
    return scanners


def get_scanners() -> Dict[str, Scanner]:
    """All discovered scanners keyed by name (sqli, xss, ssrf, ssti, xxe)."""
    return _discover()


def get_scanner(name: str) -> Optional[Scanner]:
    return get_scanners().get(name)


def scan_file(path: Union[str, Path], code: Optional[str] = None) -> List[Finding]:
    """Run every scanner against a file; returns List[Finding]."""
    if code is None:
        try:
            code = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    findings: List[Finding] = []
    for scanner in get_scanners().values():
        if scanner.name == "solidity" and Path(path).suffix.lower() != ".sol":
            continue
        try:
            findings.extend(scanner.detect(code, path=str(path)))
        except Exception:
            continue
    findings.sort(key=lambda f: (f.file, f.line, f.vuln_type))
    return findings
