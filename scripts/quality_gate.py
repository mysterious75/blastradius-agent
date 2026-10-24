#!/usr/bin/env python3
"""Enforce PROJECT_RULES.md mechanically (fail-closed).

Checks a change set (``git diff <base>``) for the rules an agent can
actually verify:

1. lint/format clean (``ruff``), unless ``--no-lint``
2. every changed source module is referenced by a test
3. the change ships unit + integration tests (and e2e/adversarial for
   user-facing / security-sensitive paths), detected via pytest markers
4. no high-signal secrets in added lines, unless ``--no-secrets``

Exit 0 only when every check passes. ``--json`` prints the machine form,
``--checklist-out`` writes the human checklist for the PR body.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence, Set, Tuple

RULES_VERSION = "1.0"

USER_FACING_PREFIXES = (
    "blastradius/cli/",
    "blastradius/verified_pr/",
    "blastradius/ci/",
    "blastradius/api/",
    "blastradius/dashboard/",
    "blastradius/hunter/",
    "scripts/pr_scan.py",
    ".github/workflows/",
    "bitbucket-pipelines.yml",
)

SECURITY_PREFIXES = (
    "blastradius/sandbox/",
    "blastradius/verified_pr/",
    "blastradius/patcher/",
    "blastradius/ci/",
    "blastradius/api/",
    "blastradius/hunter/",
    "blastradius/net/",
    "scripts/pr_scan.py",
    "scripts/self_attack.py",
)

TIERS = ("unit", "integration", "e2e", "adversarial")

SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)

_MARKER_RE = re.compile(r"pytest\.mark\.(unit|integration|e2e|adversarial)\b")
_WORD = re.compile(r"[^A-Za-z0-9_]+")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False


@dataclass
class Report:
    base: str
    rules_version: str = RULES_VERSION
    changed: List[str] = field(default_factory=list)
    required: List[str] = field(default_factory=list)
    checks: List[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def failed(self) -> List[Check]:
        return [c for c in self.checks if not c.ok]


def _run(cmd: Sequence[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git_changed_files(repo: Path, base: str) -> List[str]:
    """Files added/modified between ``base`` and the working tree."""
    proc = _run(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "diff",
            "--name-only",
            "--diff-filter=AM",
            "-z",
            base,
        ],
        repo,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git diff {base} failed: {proc.stderr.strip()}")
    untracked = _run(
        ["git", "-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "-z"],
        repo,
    )
    names = [line.strip() for line in proc.stdout.split("\0") if line.strip()]
    if untracked.returncode == 0:
        names += [line.strip() for line in untracked.stdout.split("\0") if line.strip()]
    return sorted({line.replace("\\", "/") for line in names if line.strip()})


def is_source(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (
        path.endswith(".py")
        and name != "__init__.py"
        and (path.startswith("blastradius/") or path.startswith("scripts/"))
    )


def is_test(path: str) -> bool:
    return path.startswith("tests/") and path.endswith(".py")


def import_path(path: str) -> str:
    return path[: -len(".py")].replace("/", ".")


def required_tiers(changed: Iterable[str]) -> Set[str]:
    """Minimum tier set for a change set."""
    changed = list(changed)
    sources = [p for p in changed if is_source(p)]
    if not sources:
        return set()
    tiers: Set[str] = {"unit", "integration"}
    if any(p.startswith(USER_FACING_PREFIXES) for p in sources):
        tiers.add("e2e")
    if any(p.startswith(SECURITY_PREFIXES) for p in sources):
        tiers.add("adversarial")
    return tiers


def test_tiers(text: str) -> Set[str]:
    return set(_MARKER_RE.findall(text))


def changed_test_tiers(repo: Path, changed: Iterable[str]) -> Set[str]:
    tiers: Set[str] = set()
    for path in changed:
        if is_test(path) and (repo / path).exists():
            tiers |= test_tiers((repo / path).read_text(encoding="utf-8", errors="replace"))
    return tiers


def _test_corpus(repo: Path) -> List[str]:
    corpus = []
    tests_dir = repo / "tests"
    if not tests_dir.is_dir():
        return corpus
    for path in tests_dir.rglob("*.py"):
        corpus.append(path.read_text(encoding="utf-8", errors="replace"))
    return corpus


def _referenced(path: str, corpus: Sequence[str]) -> bool:
    imp = import_path(path)
    stem = path.rsplit("/", 1)[-1][: -len(".py")]
    needles = {imp, f'"{imp}"', f"'{imp}'", f"scripts/{stem}", path}
    if len(stem) >= 4:
        needles.add(stem)
    for text in corpus:
        if any(needle in text for needle in needles):
            return True
        words = set(_WORD.split(text))
        if stem in words:
            return True
    return False


def missing_test_refs(repo: Path, changed: Iterable[str]) -> List[str]:
    corpus = _test_corpus(repo)
    return [p for p in changed if is_source(p) and not _referenced(p, corpus)]


def secret_hits(repo: Path, base: str) -> List[Tuple[str, str, int]]:
    """High-signal secret patterns in *added* lines of the diff."""
    proc = _run(["git", "-c", "core.quotePath=false", "diff", "--no-color", "-U0", base], repo)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff {base} failed: {proc.stderr.strip()}")
    hits: List[Tuple[str, str, int]] = []
    current: str | None = None
    for raw in proc.stdout.splitlines():
        if raw.startswith("+++ b/"):
            current = raw[len("+++ b/") :]
            continue
        if not raw.startswith("+") or raw.startswith("+++") or current is None:
            continue
        added = raw[1:]
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(added):
                hits.append((current, name, len(hits) + 1))
    untracked = _run(
        ["git", "-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "-z"],
        repo,
    )
    if untracked.returncode == 0:
        for rel in (p.strip() for p in untracked.stdout.split("\0")):
            if not rel:
                continue
            path = repo / rel
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for num, line in enumerate(text.splitlines(), 1):
                for name, pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        hits.append((rel, name, num))
    return hits


def lint_checks(repo: Path) -> List[Check]:
    checks: List[Check] = []
    for name, cmd in (
        ("ruff-format", ["ruff", "format", "--check", "blastradius", "tests", "scripts"]),
        ("ruff-lint", ["ruff", "check", "blastradius", "tests", "scripts"]),
    ):
        proc = _run(cmd, repo)
        if proc.returncode == 127 or "not recognized" in (proc.stderr or ""):
            checks.append(Check(name, False, "ruff is not installed"))
            continue
        detail = "" if proc.returncode == 0 else (proc.stdout or proc.stderr).strip()[:800]
        checks.append(Check(name, proc.returncode == 0, detail))
    return checks


def build_report(
    repo: Path,
    base: str,
    *,
    lint: bool = True,
    secrets: bool = True,
) -> Report:
    changed = git_changed_files(repo, base)
    required = sorted(required_tiers(changed))
    report = Report(base=base, changed=changed, required=required)

    if lint:
        report.checks.extend(lint_checks(repo))
    if secrets:
        hits = secret_hits(repo, base)
        detail = "; ".join(f"{path}:{name}" for path, name, _ in hits[:5])
        report.checks.append(Check("no-secrets", not hits, detail))

    if not changed:
        report.checks.append(Check("changed", True, "no changes vs base"))
        return report

    sources = [p for p in changed if is_source(p)]
    if not sources:
        report.checks.append(Check("source-change", True, "docs/config-only change"))
        return report

    missing = missing_test_refs(repo, sources)
    report.checks.append(
        Check(
            "test-reference",
            not missing,
            "unreferenced: " + ", ".join(missing[:8]) if missing else "all sources referenced",
        )
    )

    tiers = changed_test_tiers(repo, changed)
    missing_tiers = [t for t in required if t not in tiers]
    report.checks.append(
        Check(
            "test-tiers",
            not missing_tiers,
            f"missing markers: {', '.join(missing_tiers)} (found: {sorted(tiers) or 'none'})"
            if missing_tiers
            else f"found: {sorted(tiers)}",
        )
    )
    return report


def render_checklist(report: Report) -> str:
    lines = [
        f"<!-- blastradius-quality-gate v{report.rules_version} -->",
        f"### Quality gate — base `{report.base}`",
        "",
        f"Changed: {len(report.changed)} file(s) · required tiers: "
        f"{', '.join(report.required) if report.required else 'none (docs/config only)'}",
        "",
    ]
    for check in report.checks:
        mark = "x" if check.ok else " "
        note = "" if check.ok else f" — {check.detail}"
        lines.append(f"- [{mark}] `{check.name}`{note}")
    if report.ok:
        lines.append("\nGate: **PASS**")
    else:
        lines.append(f"\nGate: **FAIL** ({len(report.failed())} check(s))")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Enforce PROJECT_RULES.md")
    ap.add_argument("--repo", default=".", help="repository root")
    ap.add_argument("--base", default="HEAD~1", help="git ref to diff against")
    ap.add_argument("--no-lint", action="store_true", help="skip ruff")
    ap.add_argument("--no-secrets", action="store_true", help="skip secret scan")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--checklist-out", default="", help="write the Markdown checklist here")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    try:
        report = build_report(repo, args.base, lint=not args.no_lint, secrets=not args.no_secrets)
    except RuntimeError as exc:
        print(f"[gate] ERROR: {exc}", file=sys.stderr)
        return 2

    checklist = render_checklist(report)
    if args.checklist_out:
        Path(args.checklist_out).write_text(checklist, encoding="utf-8")
    if args.json:
        payload = asdict(report)
        payload["ok"] = report.ok
        print(json.dumps(payload, indent=2))
    else:
        print(checklist, end="")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
