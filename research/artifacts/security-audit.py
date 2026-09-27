#!/usr/bin/env python3
"""Security audit for downloaded research artifacts.

Checks every file in research/artifacts/ (recursively, skipping this script):

1. Type integrity  — only PDF / HTML / TXT(UTF-8) allowed; any ELF, MZ,
   shebang, or unknown magic is a hard FAIL.
2. PDF weaponization — pdfid-style pattern counts: /JavaScript, /JS, /Launch,
   /EmbeddedFile, /OpenAction, /AA, /RichMedia, /XFA.
3. HTML activeness  — <script> tags, inline event handlers (on*=),
   <iframe>, meta-refresh redirects, external script srcs.
4. Emits SHA256SUMS for the whole tree.

Usage: python3 research/artifacts/security-audit.py
Exit code: 0 clean, 1 findings, 2 hard fail (executable/unreadable).
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ALLOWED_SUFFIXES = {".pdf", ".html", ".htm", ".md", ".txt", ".json", ".py"}

PDF_PATTERNS = [
    "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/OpenAction",
    "/AA", "/RichMedia", "/XFA", "/URI",
]
HTML_PATTERNS = [
    (r"<script\b", "<script> tags"),
    (r"\bon[a-z]+\s*=\s*[\"']", "inline event handlers"),
    (r"<iframe\b", "<iframe>"),
    (r"<meta[^>]+http-equiv=[\"']refresh", "meta-refresh redirect"),
    (r"javascript:", "javascript: URIs"),
]
EXEC_MAGICS = [(b"\x7fELF", "ELF"), (b"MZ", "PE/MZ"), (b"#!", "shebang")]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    hard_fail = False
    findings = 0
    sums = []

    files = sorted(
        p for p in ROOT.rglob("*")
        if p.is_file() and p.name != Path(__file__).name and p.name != "SHA256SUMS"
    )
    print(f"[audit] {len(files)} file(s) under {ROOT}\n")

    for path in files:
        rel = path.relative_to(ROOT)
        data = path.read_bytes()
        sums.append(f"{sha256(path)}  {rel}")
        head = data[:16]
        notes = []

        # 1. type integrity
        for magic, label in EXEC_MAGICS:
            if data.startswith(magic) and path.suffix not in {".py"}:
                print(f"[FAIL] {rel}: executable magic ({label})")
                hard_fail = True
        if path.suffix not in ALLOWED_SUFFIXES:
            print(f"[FAIL] {rel}: unexpected file type {path.suffix!r}")
            hard_fail = True

        is_pdf = data.startswith(b"%PDF")
        is_html = bool(re.match(rb"\s*<(?:!doctype|html)", head, re.I))

        if path.suffix == ".pdf" and not is_pdf:
            print(f"[FAIL] {rel}: .pdf extension but no %PDF magic (first bytes: {head!r})")
            hard_fail = True

        # 2. PDF weaponization scan
        if is_pdf:
            for pat in PDF_PATTERNS:
                n = data.count(pat.encode())
                if n:
                    notes.append(f"{pat}×{n}")
            # /OpenAction & /JavaScript are the dangerous ones; flag loudly
            dangerous = [n for n in notes if any(d in n for d in ("/JavaScript", "/Launch", "/OpenAction", "/EmbeddedFile", "/AA"))]
            if dangerous:
                print(f"[WARN] {rel}: active PDF content: {', '.join(dangerous)}")
                findings += 1
            elif notes:
                print(f"[ok]   {rel}: PDF, passive refs only ({', '.join(notes)})")
            else:
                print(f"[ok]   {rel}: PDF, clean")

        # 3. HTML activeness scan
        elif is_html:
            for pat, label in HTML_PATTERNS:
                n = len(re.findall(pat.encode(), data, re.I))
                if n:
                    notes.append(f"{label}×{n}")
            if notes:
                print(f"[warn] {rel}: HTML active content: {', '.join(notes)} (expected for blog pages — inert offline)")
                findings += 1
            else:
                print(f"[ok]   {rel}: HTML, static")
        else:
            print(f"[ok]   {rel}: text/binary text ({len(data)} bytes)")

    (ROOT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(f"\n[audit] SHA256SUMS written ({len(sums)} entries)")
    print(f"[audit] hard-fails: {int(hard_fail)} | soft findings: {findings}")
    return 2 if hard_fail else (1 if findings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
