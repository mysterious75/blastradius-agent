"""Prometheus repo bootstrap — puts the prometheus repo root on sys.path.

Prometheus is a ``src``-layout package (import root ``src``) that is not
pip-installed. Set ``PROMETHEUS_ROOT`` to its repo root (the directory
containing the ``src/`` package); it defaults to ``../prometheus`` relative to
this project.
"""

import os
import sys
from pathlib import Path

_PROMETHEUS_ROOT = os.getenv(
    "PROMETHEUS_ROOT",
    str(Path(__file__).resolve().parents[2] / "prometheus"),
)


def ensure_prometheus_importable() -> None:
    """Add the prometheus repo root to sys.path so ``src.*`` imports resolve."""
    if any(p == _PROMETHEUS_ROOT for p in sys.path):
        return
    if not (Path(_PROMETHEUS_ROOT) / "src").is_dir():
        raise ImportError(
            f"Prometheus repo not found at {_PROMETHEUS_ROOT}. "
            "Point PROMETHEUS_ROOT at the prometheus repo root (the directory "
            "containing its src/ package)."
        )
    sys.path.insert(0, _PROMETHEUS_ROOT)
