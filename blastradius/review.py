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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from blastradius.hunter.scanner import SKIP_DIRS
from blastradius.providers.client import LLMClient, LLMUnavailableError
from blastradius.security.input_validator import validate_repo_path, validate_target_code

REVIEW_PROMPT = (
    "You are auditing ONE source-file chunk of Cloudflare workerd (a Workers runtime).\n"
    "Find crash-prone code reachable from standard Worker primitives (fetch, streams,\n"
    "crypto, HTMLRewriter, WebSocket, JSRPC, WebAssembly): panics/aborts, unchecked\n"
    "unwrap()/expect(), out-of-bounds indexing, integer overflow in size calculations,\n"
    "unbounded recursion, use-after-free.\n"
    "DO NOT report:\n"
    "- deliberate abort/termination paths (KJ_UNREACHABLE, kj::throwFatalException,\n"
    "  KJ_ASSERT* invariant guards, KJ_UNIMPLEMENTED) unless user-controlled input can\n"
    "  deterministically reach them across a trust boundary\n"
    "- lifetime issues where the callee copies the value synchronously before any\n"
    "  temporary dies (verify the callee body first)\n"
    "- hardening-only or missing-default robustness nits with no demonstrated reachability\n"
    "- anything not at the exact line you are quoting\n"
    "Reply with exactly one line per issue:\n"
    "  FILE:LINE | SEVERITY | ONE-LINE REASON\n"
    "or exactly NO_ISSUES if none. Only report issues you are confident about.\n\n"
)

VERIFY_PROMPT = (
    "VERIFY THIS CLAIM against the source window below.\n"
    "CLAIM: {reason}\n"
    "SOURCE around line {line}:\n"
    "{context}\n"
    "The claim is REJECTED if any of:\n"
    "- the termination is by design (KJ_UNREACHABLE / kj::throwFatalException / KJ_ASSERT* /\n"
    "  KJ_UNIMPLEMENTED abort or invariant paths) with no user-controlled cross-boundary path\n"
    "- the claimed lifetime is safe (e.g. the callee copies the value synchronously before\n"
    "  any temporary dies)\n"
    "- the claim does not match the code at the stated line, or impact is hardening-only\n"
    "- reachability from a Worker primitive is not demonstrated\n"
    "Reply exactly one of:\n"
    "  CONFIRMED: one-line justification\n"
    "  REJECTED: one-line reason\n"
)

MAX_CHUNK_BYTES = 16 * 1024  # small chunks = fast LLM turns, fewer timeouts

DEFAULT_EXTS = (".cc", ".cxx", ".cpp", ".h", ".hh", ".ts", ".js")


def _iter_files(root: Path, exts: Tuple[str, ...]):
    for ext in exts:
        for path in root.rglob(f"*{ext}"):
            if any(part in SKIP_DIRS or part.endswith("-test") for part in path.parts):
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


FAILURE_STREAK_STOP = 4

VERIFY_WINDOW = 30  # source lines around the flag shown to the verifier


def verify_finding(finding: dict, source_text: str, client) -> dict:
    """Two-stage accuracy gate: the LLM re-checks its own flag against the
    real source window and must CONFIRM it. Fail-closed: anything other than
    an explicit CONFIRMED prefix is treated as rejected.
    """
    line = int(finding.get("line", 0))
    lines = source_text.splitlines()
    start = max(0, line - 1 - VERIFY_WINDOW)
    context = "\n".join(lines[start:start + 2 * VERIFY_WINDOW + 1])
    prompt = VERIFY_PROMPT.format(reason=finding.get("reason", ""), line=line, context=context)
    try:
        reply = client.chat([{"role": "user", "content": prompt}])
    except Exception as exc:
        return {**finding, "verified": False, "verify_reason": f"verify call failed: {exc}"}
    upper = (reply or "").upper()
    if upper.startswith("CONFIRMED"):
        return {**finding, "verified": True, "verify_reason": reply}
    return {**finding, "verified": False, "verify_reason": reply}


def _review_one(args):
    """Review a single chunk; retries once on transient failure; flags that
    survive the scan are then run through the verification gate.

    Returns {"status": "ok"|"skipped"|"failed", "path", "findings", "rejected"}.
    """
    path, start_line, chunk, source_text, client = args
    for attempt in range(2):
        try:
            validate_target_code(REVIEW_PROMPT + chunk)
        except ValueError:
            return {"status": "skipped", "path": path, "findings": [], "rejected": []}
        try:
            reply = client.chat([{"role": "user", "content": REVIEW_PROMPT + chunk}])
        except Exception:
            if attempt == 0:
                import time as _time

                _time.sleep(0.5)  # brief backoff before the retry
            continue
        findings, rejected = [], []
        for finding in _parse_findings(reply, path, start_line):
            verified = verify_finding(finding, source_text, client)
            if verified["verified"]:
                findings.append(verified)
            else:
                rejected.append(verified)
        return {"status": "ok", "path": path, "findings": findings, "rejected": rejected}
    return {"status": "failed", "path": path, "findings": [], "rejected": []}


def review_repo(
    repo_path: str,
    limit: int = 100,
    exts: Tuple[str, ...] = DEFAULT_EXTS,
    client=None,
    timeout: int = 120,
    workers: int = 4,
) -> List[dict]:
    """Review up to ``limit`` source files in parallel; returns LLM-flagged findings.

    Chunks run concurrently (``workers`` threads) for throughput; each chunk is
    retried once on transient failures; after ``FAILURE_STREAK_STOP``
    consecutive failures the review stops early (provider down) and returns
    whatever was found so far. Findings stream to stderr as they arrive so a
    slow run still shows progress.
    """
    root = Path(validate_repo_path(repo_path))
    client = client or LLMClient(timeout=timeout)

    tasks = []
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
            tasks.append((path, start_line, chunk, text, client))

    findings: List[dict] = []
    rejected_count = 0
    skipped = failed = 0
    streak = 0
    total = len(tasks)
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_review_one, t): t for t in tasks}
        try:
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res["status"] == "ok":
                    streak = 0
                    for f in res["findings"]:
                        print(
                            f"[+] {f['file']}:{f['line']} {f['severity']} — {f['reason']}",
                            file=sys.stderr,
                        )
                    findings.extend(res["findings"])
                    for r in res.get("rejected", []):
                        rejected_count += 1
                        print(
                            f"[-] rejected: {r['file']}:{r['line']} — {r['verify_reason'][:100]}",
                            file=sys.stderr,
                        )
                elif res["status"] == "skipped":
                    skipped += 1
                else:
                    streak += 1
                    failed += 1
                    print(f"[!] chunk failed: {res['path']}", file=sys.stderr)
                    if streak >= FAILURE_STREAK_STOP:
                        print(
                            "[!] too many consecutive failures — provider flaky; stopping early",
                            file=sys.stderr,
                        )
                        break
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    if skipped:
        print(f"[*] {skipped} chunk(s) skipped by the prompt-injection guard", file=sys.stderr)
    if failed:
        print(f"[!] {failed} chunk(s) failed (timeouts/errors) — partial results", file=sys.stderr)
    print(
        f"[*] reviewed {done}/{total} chunk(s) — {len(findings)} confirmed, "
        f"{rejected_count} rejected by verification",
        file=sys.stderr,
    )
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="blastradius-review",
        description="LLM code review for crash-prone patterns (workerd-style).",
    )
    parser.add_argument("repo", help="local repo path to review")
    parser.add_argument("--limit", type=int, default=100, help="max files to review")
    parser.add_argument("--timeout", type=int, default=120, help="LLM per-request timeout (s)")
    parser.add_argument("--workers", type=int, default=4, help="parallel chunk workers")
    parser.add_argument("--ext", nargs="*", default=list(DEFAULT_EXTS), help="file extensions")
    args = parser.parse_args(argv)

    findings = review_repo(
        args.repo,
        limit=args.limit,
        exts=tuple(args.ext),
        timeout=args.timeout,
        workers=args.workers,
    )
    print(json.dumps(findings, indent=2, default=str))
    print(f"{len(findings)} finding(s) — LLM-flagged; verify each before reporting")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
