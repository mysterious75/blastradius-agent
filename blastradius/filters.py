"""Shared false-positive filters for scan findings.

Vendored/third-party code (``node_modules/``, ``vendor/``, minified bundles)
dominates findings on real repositories but is almost never the operator's
code to fix. Centralized here so every entry point (``hunter``, ``auto_hunt``,
agents, pipeline) applies the identical filter.
"""

from pathlib import Path
from typing import List

# Vendored/noise path parts excluded from findings before sandbox validation.
FP_PATH_PARTS = frozenset(
    {
        "node_modules",
        "vendor",
        "dist",
        "libs",
        "assets",
        "tests",
        "docs",
        "examples",
        "migrations",
        "__pycache__",
        "static",
        "public",
    }
)


def fp_filter(findings: List) -> List:
    """Drop vendored/tests/docs/minified candidates; return survivors."""
    survivors = []
    for f in findings:
        parts = Path(f.file).parts
        if any(p in FP_PATH_PARTS for p in parts):
            continue
        if "min." in Path(f.file).name:
            continue
        survivors.append(f)
    return survivors
