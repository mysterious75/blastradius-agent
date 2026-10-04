"""Re-test — apply each generated patch to a scratch copy of the real tree.

Two evidence levels, strongest first:

1. **Exploit replay** (``method="exploit-replay"``): the real patched
   function is harnessed and the REAL exploit payloads (canonical PoC +
   mutated bypass battery) are executed against it in the sandbox, plus a
   benign-input check. ``FIXED`` here means the exploit path is demonstrably
   closed — strictly stronger than scanner silence.
2. **Static rescan** (``method="static-rescan"``): fallback when replay is
   inapplicable (unsupported shape/language) or inconclusive. ``FIXED`` here
   means only that the same scanners no longer flag the type — weaker
   evidence, labeled as such.

- ``STILL_VULNERABLE`` — the patch applied but a payload still succeeds
  (replay) or the scanner still flags the type (static fallback);
- ``UNVERIFIABLE`` — no patch, or the patch could not be applied safely, or
  neither evidence level could run. Fail-closed: the gate blocks.

The synthetic sandbox PoC is never re-run as fix evidence: it proves the
*pattern* is exploitable, so it would still succeed against a synthetic
reproduction. Any *new* vulnerability types the patch introduces on the same
file are reported in ``introduced``.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

from scripts.autofix_pr import apply_patches

from blastradius.hunter.scanner import CVEHunter, Finding
from blastradius.verified_pr.models import (
    RETEST_FIXED,
    RETEST_STILL_VULNERABLE,
    RETEST_UNVERIFIABLE,
    RetestOutcome,
)
from blastradius.verified_pr.replay import (
    REPLAY_BLOCKED,
    REPLAY_STILL_VULNERABLE,
    extract_harness,
    supported_types,
    verify_fix,
)


def _repo_relative(repo_root: str, file: str) -> str:
    """Finding file as a POSIX repo-relative path (best-effort)."""
    try:
        return Path(file).resolve().relative_to(Path(repo_root).resolve()).as_posix()
    except ValueError:
        return str(file).replace("\\", "/")


def _types_by_file(findings: List[Finding], repo_root: str) -> Dict[str, set]:
    by_file: Dict[str, set] = {}
    for f in findings:
        by_file.setdefault(_repo_relative(repo_root, f.file), set()).add(f.vuln_type)
    return by_file


def _align_entry(tree: Path, rel: str, line_no: int, entry: dict) -> dict:
    """Align a patch to the raw indented source line.

    Scanners report ``payload`` stripped, but the file line carries
    indentation — exact-match application needs the raw line. When the
    stripped original is found inside the raw line, the entry is rewritten to
    the raw form (indentation preserved); otherwise it is left untouched and
    application will honestly fail closed.
    """
    entry = dict(entry)
    original = entry.get("original_code", "") or ""
    patched = entry.get("patched_code", "") or ""
    stripped = original.strip()
    if not stripped or "\n" in stripped or "\n" in patched.strip():
        return entry
    try:
        raw_lines = (tree / rel).read_text(encoding="utf-8").splitlines()
    except OSError:
        return entry
    if not (1 <= line_no <= len(raw_lines)):
        return entry
    raw = raw_lines[line_no - 1]
    if stripped not in raw:
        return entry
    entry["original_code"] = raw
    entry["patched_code"] = raw.replace(stripped, patched.strip(), 1)
    return entry


def _static_fallback(rel: str, f: Finding, pre_types, post_types) -> RetestOutcome:
    """Weaker evidence: scanner silence on the patched tree."""
    still = f.vuln_type in post_types.get(rel, set())
    introduced = sorted(post_types.get(rel, set()) - pre_types.get(rel, set()))
    if still:
        return RetestOutcome(
            file=rel,
            line=f.line,
            vuln_type=f.vuln_type,
            status=RETEST_STILL_VULNERABLE,
            detail="patch applied but the scanner still flags this type",
            introduced=introduced,
            method="static-rescan",
        )
    return RetestOutcome(
        file=rel,
        line=f.line,
        vuln_type=f.vuln_type,
        status=RETEST_FIXED,
        detail="patch applied; scanners no longer flag this type (no exploit replay available)",
        introduced=introduced,
        method="static-rescan",
    )


def retest_patches(
    repo: str,
    items: List[Tuple[Finding, dict]],
    min_confidence: float = 0.7,
) -> List[RetestOutcome]:
    """Re-test ``items`` (each a ``(finding, patch_entry)`` pair).

    ``patch_entry`` carries ``file``/``line``/``vuln_type`` plus
    ``original_code``/``patched_code``/``source`` (the same shape the PR scan
    stores in its results JSON). Returns one outcome per item, in order.
    Never raises: unexpected errors become ``UNVERIFIABLE`` with a detail.
    """
    outcomes: List[RetestOutcome] = []
    if not items:
        return outcomes

    tmp = Path(tempfile.mkdtemp(prefix="blastradius-retest-"))
    try:
        for name in os.listdir(repo):
            if name == ".git":
                continue
            src = Path(repo) / name
            dst = tmp / name
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)

        hunter = CVEHunter(min_confidence=min_confidence)
        try:
            pre_types = _types_by_file(hunter.scan_repo(str(tmp)), str(tmp))
        except Exception as exc:
            return [
                RetestOutcome(
                    file=_repo_relative(repo, f.file),
                    line=f.line,
                    vuln_type=f.vuln_type,
                    status=RETEST_UNVERIFIABLE,
                    detail=f"pre-patch rescan failed: {exc}",
                    method="unverifiable",
                )
                for f, _ in items
            ]

        entries = []
        rels = []
        for f, patch in items:
            rel = _repo_relative(repo, f.file)
            rels.append(rel)
            entry = dict(patch)
            # Apply inside the scratch tree: resolve the real file to its copy.
            entry["file"] = str(tmp / rel)
            entries.append(_align_entry(tmp, rel, f.line, entry))
        try:
            # apply_patches returns one result per entry, in order — join back
            # by position (its file field is repo-relative, not the tmp path).
            applied_results = apply_patches(tmp, entries)
        except Exception as exc:
            return [
                RetestOutcome(
                    file=_repo_relative(repo, f.file),
                    line=f.line,
                    vuln_type=f.vuln_type,
                    status=RETEST_UNVERIFIABLE,
                    detail=f"patch application crashed: {exc}",
                    method="unverifiable",
                )
                for f, _ in items
            ]

        try:
            post_types = _types_by_file(hunter.scan_repo(str(tmp)), str(tmp))
        except Exception as exc:
            return [
                RetestOutcome(
                    file=_repo_relative(repo, f.file),
                    line=f.line,
                    vuln_type=f.vuln_type,
                    status=RETEST_UNVERIFIABLE,
                    detail=f"post-patch rescan failed: {exc}",
                    method="unverifiable",
                )
                for f, _ in items
            ]

        for (f, _patch), rel, result in zip(items, rels, applied_results):
            if result.get("status") != "applied":
                outcomes.append(
                    RetestOutcome(
                        file=rel,
                        line=f.line,
                        vuln_type=f.vuln_type,
                        status=RETEST_UNVERIFIABLE,
                        detail=f"patch not applied: {result.get('reason', 'unknown')}",
                        method="unverifiable",
                    )
                )
                continue
            introduced = sorted(post_types.get(rel, set()) - pre_types.get(rel, set()))
            # Level 1: exploit replay against the real patched function.
            replayed = False
            if f.vuln_type in supported_types():
                try:
                    patched_content = (tmp / rel).read_text(encoding="utf-8")
                    harness, _reason = extract_harness(patched_content, f.line)
                except OSError as exc:
                    harness, _reason = None, f"cannot read patched file: {exc}"
                if harness is not None:
                    replayed = True
                    replay_note = ""
                    try:
                        rr = verify_fix(f.vuln_type, harness)
                    except Exception as exc:
                        rr = None
                        replay_note = f" (exploit replay crashed: {exc})"
                    if rr is not None and rr.status == REPLAY_BLOCKED:
                        outcomes.append(
                            RetestOutcome(
                                file=rel,
                                line=f.line,
                                vuln_type=f.vuln_type,
                                status=RETEST_FIXED,
                                detail=rr.evidence,
                                introduced=introduced,
                                method="exploit-replay",
                                evidence=rr.evidence,
                            )
                        )
                        continue
                    if rr is not None and rr.status == REPLAY_STILL_VULNERABLE:
                        outcomes.append(
                            RetestOutcome(
                                file=rel,
                                line=f.line,
                                vuln_type=f.vuln_type,
                                status=RETEST_STILL_VULNERABLE,
                                detail=rr.evidence,
                                introduced=introduced,
                                method="exploit-replay",
                                evidence=rr.evidence,
                            )
                        )
                        continue
                    # INCONCLUSIVE (or crashed): fall through to static.
            # Level 2: static rescan fallback (weaker, labeled as such).
            fallback = _static_fallback(rel, f, pre_types, post_types)
            if replayed:
                fallback.detail += (
                    " (exploit replay inconclusive)" if not replay_note else replay_note
                )
            outcomes.append(fallback)
        return outcomes
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
