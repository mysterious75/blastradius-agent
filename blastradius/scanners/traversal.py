"""TraversalScanner — self-contained path traversal detection.

Sinks: open(var), file_get_contents, fs.readFile*, send_file, Path.join,
os.path.join, and file-deletion sinks (unlink/os.remove/os.unlink/os.rmdir/
shutil.rmtree) with user-controlled paths. Safe markers (abspath, realpath,
resolve, secure_filename) are skipped.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    has_source,
    make_finding,
    references_variable,
    scan_lines,
)

_SINKS = [
    r"\bopen\s*\(\s*[A-Za-z_$][\w$]*",
    r"\bopen\s*\([^)]*\b(?:file|path|filename|name)\b\s*,",
    r"\bfile_get_contents\s*\(",
    r"\bfread\s*\([^)]*,?\s*[A-Za-z_$]",
    r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(",
    r"\breadFileSync\s*\(",
    r"\b(?:send_file|FileResponse|static_file|sendfile)\s*\(",
    r"\bnew\s+File\s*\(",
    r"\bgetResourceAsStream\s*\(",
    r"\bPath\.join\s*\([^)]*[A-Za-z_$]",
    r"\bos\.path\.join\s*\([^)]*[A-Za-z_$]",
    r"\b(?:unlink|os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree)\s*\(",
    r"\bPath\s*\(\s*[A-Za-z_$][\w$]*",
]
_SAFE = re.compile(
    r"abspath|realpath|normpath|resolve\s*\(|secure_filename|"
    r"secureJoin|safe_join|normalize_path|os\.path\.(?:basename|dirname)|"
    r"user\.file|file_storage",
    re.I,
)


class TraversalScanner:
    """Pattern-based path traversal scanner."""

    name = "traversal"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)
        if _SAFE.search(code):  # file-level path hardening suppresses traversal
            return []

        def check(line, idx):
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.7
            return make_finding(
                path,
                idx,
                "traversal",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-22",
                "Path traversal: user-controlled input flows into a file path operation.",
                "Resolve paths with os.path.abspath and verify the result stays inside a known root.",
            )

        return scan_lines(code, path, check)
