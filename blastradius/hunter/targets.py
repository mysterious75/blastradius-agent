"""Hardcoded Phase-3 target list (10K+ star, intentionally vulnerable projects).

The CLI falls back to DEFAULT_TARGETS[0] when no --target is given; any
GitHub URL or local path can also be passed explicitly.
"""

DEFAULT_TARGETS = [
    "https://github.com/WebGoat/WebGoat",
    "https://github.com/digininja/DVWA",
    "https://github.com/juice-shop/juice-shop",
]
