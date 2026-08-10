"""LLM code review for crash-prone patterns (workerd-style runtime hunting).

Deterministic pattern scanners find web-vuln sinks but not runtime crashes
(panics/aborts, unchecked unwrap/expect, OOB indexing, overflow in size
calculations, unbounded recursion, use-after-free). This walks source files,
sends each chunk to the selected LLM with a focused crash-audit prompt, and
prints only the flagged locations. No pattern-level FPs — the candidate pool
is exact, though LLM flags still need human verification before reporting.

Run:  python -m blastradius.review <repo-path> [--limit N] [--ext .cc .h .ts .js]
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from blastradius.hunter.scanner import SKIP_DIRS
from blastradius.providers.client import LLMClient, LLMUnavailableError
from blastradius.security.input_validator import validate_repo_path, validate_target_code

REVIEW_PROMPT = (
    "You are auditing ONE source-file chunk of Cloudflare workerd (a Workers runtime).\n"
    "Find crash-prone code reachable from standard Worker primitives (fetch, streams,\n"
    "crypto, HTMLRewriter, WebSocket, JSRPC): panics/aborts, unchecked unwrap()/expect(),\n"
    "out-of-bounds indexing, integer overflow in size calculations, unbounded recursion,\n"
    "use-after-free. Reply with exactly one line per issue:\n"
    "  FILE:LINE | SEVERITY | ONE-LINE REASON\n"
    "or exactly NO_ISSUES if none. Do not report style, theory, or hardening-only items.\n\n"
)

MAX_CHUNK_BYTES = 16 * 1024  # small chunks = fast LLM turns, fewer timeouts

DEFAULT_EXTS = (".cc", ".cxx", ".cpp", ".h", ".hh", ".ts", ".js")


def _iter_files(root: Path, exts: Tuple[str, ...]):
    for ext in exts:
        for path in root.rglob(f"*{ext}"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            stem = path.stem
            if (stem.endswith("_test") or stem.startswith("test_")
                    or stem.endswith(".test") or stem.endswith(".spec")
                    or stem.endswith("_spec")):
                continue
            yield path


def _chunks(text: str, base_line: int = 1) -> List[Tuple[str, int]]:
    """Split code into chunks under MAX_CHUNK_BYTES; each carries its 1-based
    start line so LLM-reported line numbers can be mapped back to the file."""
    chunks = []
    lines = text.splitlines()
    chunk, start, size = [], base_line, 0
    for i, line in enumerate(lines, start=base_line):
        chunk.append(line)
        if start is None:
            start = i
        size += len(line.encode("utf-8")) + 1
        if size >= MAX_CHUNK_BYTES:
            chunks.append(("\n".join(chunk), start))
            chunk, start, size = [], None, 0
    if chunk:
        chunks.append(("\n".join(chunk), start or base_line))
    return chunks


def _parse_findings(reply: str, path: Path, start_line: int) -> List[dict]:
    findings = []
    for raw in reply.splitlines():
        line = raw.strip()
        if not line or line.upper().startswith("NO_ISSUES"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        loc = parts[0]
        n = 0
        if ":" in loc:
            try:
                n = int(loc.rsplit(":", 1)[1])
            except ValueError:
                n = 0
        findings.append(
            {
                "file": str(path),
                "line": start_line + max(n, 1) - 1,
                "severity": parts[1],
                "reason": "|".join(parts[2:]),
            }
        )
    return findings


def review_repo(
    repo_path: str,
    limit: int = 100,
    exts: Tuple[str, ...] = DEFAULT_EXTS,
    client=None,
    timeout: int = 120,
) -> List[dict]:
    """Review up to ``limit`` source files; returns LLM-flagged findings.

    ``timeout`` is the per-request LLM timeout in seconds (default 120 — the
    client's default 30s is too short for large code chunks).
    """
    root = Path(validate_repo_path(repo_path))
    client = client or LLMClient(timeout=timeout)
    findings: List[dict] = []
    skipped = 0
    failed = 0
    seen = 0
    for path in _iter_files(root, exts):
        if seen >= limit:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen += 1
        for chunk, start_line in _chunks(text):
            try:
                validate_target_code(REVIEW_PROMPT + chunk)
            except ValueError:
                skipped += 1
                continue
            try:
                reply = client.chat([{"role": "user", "content": REVIEW_PROMPT + chunk}])
            except Exception as exc:  # a slow/failed chunk must not abort the review
                failed += 1
                print(f"[!] chunk failed ({type(exc).__name__}): {path}", file=sys.stderr)
                continue
            findings.extend(_parse_findings(reply, path, start_line))
    if skipped:
        print(f"[*] {skipped} chunk(s) skipped by the prompt-injection guard", file=sys.stderr)
    if failed:
        print(f"[!] {failed} chunk(s) failed (timeouts/errors) — partial results", file=sys.stderr)
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-review",
        description="LLM code review for crash-prone patterns (workerd-style).",
    )
    parser.add_argument("repo", help="local repo path to review")
    parser.add_argument("--limit", type=int, default=100, help="max files to review")
    parser.add_argument("--timeout", type=int, default=120, help="LLM per-request timeout (s)")
    parser.add_argument("--ext", nargs="*", default=list(DEFAULT_EXTS), help="file extensions")
    args = parser.parse_args(argv)

    findings = review_repo(
        args.repo, limit=args.limit, exts=tuple(args.ext), timeout=args.timeout
    )
    print(json.dumps(findings, indent=2, default=str))
    print(f"{len(findings)} finding(s) — LLM-flagged; verify each before reporting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
