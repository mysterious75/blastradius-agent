"""Provider-neutral PR/change-set collection.

Sources, in order of preference:
1. an explicit unified-diff file (``--diff-file``; used by tests/demos);
2. ``git diff <base>...HEAD`` inside ``--repo`` (CI usage).

Oversized or unloadable change sets are NEVER silently marked safe: they
produce a truncated ChangeSet plus an error the policy engine turns into
ANALYSIS_ERROR under the default fail-closed policy.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from blastradius.ci.models import ChangeSet, FileChange, Hunk, Policy

DEFAULT_EXCLUDES = (
    r"(^|/)vendor/",
    r"(^|/)node_modules/",
    r"(^|/)\.git/",
    r"\.min\.js$",
    r"\.bundle\.js$",
    r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|tar\.gz|tgz|exe|dll|so|dylib|bin|dat)$",
    r"(^|/)(dist|build|out|target)/",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"poetry\.lock$",
    r"(^|/)\.cache/",
    r"coverage\.xml$",
    r"\.pyc$",
)

_DIFF_GIT_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")
_NEW_FILE_RE = re.compile(r"^new file mode")
_DELETED_FILE_RE = re.compile(r"^deleted file mode")
_BINARY_RE = re.compile(r"^Binary files .* differ")
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class DiffError(RuntimeError):
    """Raised when a change set cannot be collected."""


def _compile_excludes(patterns: List[str]) -> List[re.Pattern]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            continue
    return compiled


def is_excluded(path: str, excludes: List[re.Pattern]) -> bool:
    return any(p.search(path) for p in excludes)


def parse_unified_diff(
    text: str,
    policy: Optional[Policy] = None,
    excludes: Optional[List[str]] = None,
) -> Tuple[ChangeSet, List[str]]:
    """Parse unified diff text into a ChangeSet plus a list of errors.

    Limits come from ``policy`` (file count, byte budget, hunks/file).
    Anything over budget marks the ChangeSet truncated with a reason and
    appends an error — the caller must surface it, never swallow it.
    """
    policy = policy or Policy()
    exclude_res = _compile_excludes(list(excludes) if excludes else list(DEFAULT_EXCLUDES))
    changeset = ChangeSet()
    errors: List[str] = []
    current: Optional[FileChange] = None
    hunk: Optional[Hunk] = None
    hunk_count = 0
    total_bytes = len(text.encode("utf-8", errors="replace"))

    if total_bytes > policy.max_total_bytes:
        changeset.truncated = True
        changeset.truncation_reason = (
            f"diff size {total_bytes} bytes exceeds max_total_bytes {policy.max_total_bytes}"
        )
        errors.append(changeset.truncation_reason)
        return changeset, errors

    def flush_file() -> None:
        nonlocal current, hunk, hunk_count
        if current is not None:
            if hunk is not None:
                current.hunks.append(hunk)
                hunk = None
            if not is_excluded(current.path, exclude_res):
                changeset.files.append(current)
            else:
                changeset.excluded.append(current.path)
            current = None
            hunk_count = 0

    for raw_line in text.splitlines():
        line = raw_line
        match = _DIFF_GIT_RE.match(line)
        if match:
            flush_file()
            old_path, new_path = match.group(1), match.group(2)
            if len(changeset.files) >= policy.max_files:
                changeset.truncated = True
                changeset.truncation_reason = f"file count exceeds max_files {policy.max_files}"
                errors.append(changeset.truncation_reason)
                break
            current = FileChange(path=new_path, old_path=old_path)
            continue
        if current is None:
            continue
        if _NEW_FILE_RE.match(line):
            current.is_new = True
            continue
        if _DELETED_FILE_RE.match(line):
            current.is_deleted = True
            current.path = current.old_path or current.path
            continue
        if _BINARY_RE.match(line):
            current.is_binary = True
            changeset.excluded.append(current.path)
            # Skip binary content: mark excluded and drop the file entry.
            current = None
            hunk = None
            hunk_count = 0
            continue
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        hunk_match = _HUNK_RE.match(line)
        if hunk_match:
            if hunk is not None:
                current.hunks.append(hunk)
            hunk_count += 1
            if hunk_count > policy.max_hunks_per_file:
                changeset.truncated = True
                changeset.truncation_reason = (
                    f"{current.path}: hunks exceed max_hunks_per_file {policy.max_hunks_per_file}"
                )
                errors.append(changeset.truncation_reason)
                current = None
                hunk = None
                continue
            hunk = Hunk(old_start=int(hunk_match.group(1)), new_start=int(hunk_match.group(2)))
            continue
        if hunk is not None and (
            line.startswith("+") or line.startswith("-") or line.startswith(" ")
        ):
            hunk.lines.append(line)
    flush_file()
    return changeset, errors


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


def collect_git_diff(repo: str, base: str, head: str = "HEAD") -> str:
    """Return ``git diff base...head`` text; raise DiffError when unavailable."""
    proc = _git(repo, "diff", "--no-color", "--no-ext-diff", "-U3", f"{base}...{head}")
    if proc.returncode != 0:
        raise DiffError(f"git diff failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    if not proc.stdout.strip():
        raise DiffError("empty diff: nothing changed between base and head")
    return proc.stdout


def collect_changeset(
    repo: Optional[str] = None,
    base: str = "origin/main",
    head: str = "HEAD",
    diff_file: Optional[str] = None,
    policy: Optional[Policy] = None,
    excludes: Optional[List[str]] = None,
) -> Tuple[ChangeSet, List[str]]:
    """Collect a ChangeSet from a diff file or a git repo; never raises."""
    policy = policy or Policy()
    errors: List[str] = []
    try:
        if diff_file:
            text = Path(diff_file).read_text(encoding="utf-8", errors="replace")
            changeset = ChangeSet(base_ref="diff-file", head_ref="diff-file")
        elif repo:
            text = collect_git_diff(repo, base, head)
            changeset = ChangeSet(base_ref=base, head_ref=head)
        else:
            return ChangeSet(), ["no diff source: pass --diff-file or --repo"]
        parsed, parse_errors = parse_unified_diff(text, policy=policy, excludes=excludes)
        errors.extend(parse_errors)
        parsed.base_ref = changeset.base_ref
        parsed.head_ref = changeset.head_ref
        if not parsed.files and not parsed.truncated:
            errors.append("no analyzable files in change set")
        return parsed, errors
    except (DiffError, OSError, ValueError) as exc:
        return ChangeSet(), [f"change collection failed: {exc}"]
