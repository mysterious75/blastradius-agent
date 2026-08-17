"""pre-commit hook: block commits that introduce hard-coded secrets.

Declared in ``.pre-commit-hooks.yaml`` as ``blastradius-secrets``
(entry: ``python -m blastradius.scan_secrets_hook``).

Reads the changed files from argv (or from stdin when run by pre-commit —
the NUL/newline-separated filename protocol), runs
:class:`~blastradius.scanners.secrets.SecretScanner` on each, and exits 1
with a message if any secret is found. Lines containing
``blastradius:allow`` are skipped by the scanner itself.
"""

import sys
from typing import List, Optional

from blastradius.scanners.secrets import SecretScanner


def _collect_files(argv: List[str]) -> List[str]:
    """Changed files from argv; fall back to stdin (pre-commit protocol)."""
    if len(argv) > 1:
        return argv[1:]
    stdin = sys.stdin.read()
    if "\0" in stdin:  # pre-commit passes NUL-separated filenames
        return [f for f in stdin.split("\0") if f]
    return [f for f in stdin.splitlines() if f]


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    scanner = SecretScanner()
    hits = []
    for filename in _collect_files(argv):
        try:
            with open(filename, "r", encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except OSError:
            continue  # deleted/moved files are not a problem
        for finding in scanner.detect(code, path=filename):
            hits.append((filename, finding.line, finding.payload))
    if hits:
        print("blastradius-secrets: possible hard-coded secrets detected:")
        for filename, line, payload in hits:
            print(f"  {filename}:{line}: {payload}")
        print("Fix the leak or add 'blastradius:allow' to the line to suppress it.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
