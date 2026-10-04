"""Dependency impact — what a PR changes in the dependency manifests.

Parses the supported manifests (requirements.txt, package.json, go.mod,
Pipfile — the same set as the blast-radius graph) at ``base`` and at the
working tree, then reports added / removed / version-changed packages.

This is deliberately manifest-level, not reachability: it answers "which
dependencies did this PR touch" so reviewers see supply-chain risk, without
claiming unproven reachability analysis.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from blastradius.blast_radius.graph import parse_dependencies
from blastradius.verified_pr.models import DependencyChange

MANIFESTS = ("requirements.txt", "package.json", "go.mod", "Pipfile")


def _git_show(repo: str, ref: str, path: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", repo, "show", f"{ref}:{path}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception:
        return None
    return proc.stdout if proc.returncode == 0 else None


def _parse_tree(tree: Path) -> Dict[str, Dict[str, str]]:
    """{(manifest, name): version} for every manifest present in ``tree``."""
    out: Dict[str, Dict[str, str]] = {}
    # parse_dependencies reads manifests relative to the given root dir, so
    # each manifest is parsed from an isolated single-file temp dir.
    for manifest in MANIFESTS:
        if (tree / manifest).is_file():
            single = Path(tempfile.mkdtemp(prefix="blastradius-dep-"))
            try:
                shutil.copy2(tree / manifest, single / manifest)
                for name, version in parse_dependencies(str(single)):
                    out.setdefault(manifest, {})[name] = version or ""
            finally:
                shutil.rmtree(single, ignore_errors=True)
    return out


def dependency_impact(repo: str, base: str) -> List[DependencyChange]:
    """Diff dependency manifests between ``base`` and the working tree.

    Never raises: git/history problems yield an empty list (impact unknown,
    not impact zero — the caller reports whether a diff was available).
    """
    tmp = Path(tempfile.mkdtemp(prefix="blastradius-depbase-"))
    try:
        try:
            head = _parse_tree(Path(repo))
        except Exception:
            head = {}
        base_manifests = False
        for manifest in MANIFESTS:
            content = _git_show(repo, base, manifest)
            if content is None:
                continue
            base_manifests = True
            path = tmp / manifest
            path.write_text(content, encoding="utf-8")
        try:
            base_deps = _parse_tree(tmp) if base_manifests else {}
        except Exception:
            base_deps = {}

        changes: List[DependencyChange] = []
        for manifest in MANIFESTS:
            old = base_deps.get(manifest, {})
            new = head.get(manifest, {})
            for name in sorted(set(old) | set(new)):
                if name not in old:
                    changes.append(DependencyChange(manifest, name, "", new[name], "added"))
                elif name not in new:
                    changes.append(DependencyChange(manifest, name, old[name], "", "removed"))
                elif old[name] != new[name]:
                    kind = "changed"
                    if old[name] and new[name]:
                        try:
                            kind = (
                                "upgraded"
                                if _version_key(new[name]) > _version_key(old[name])
                                else "downgraded"
                            )
                        except Exception:
                            kind = "changed"
                    changes.append(DependencyChange(manifest, name, old[name], new[name], kind))
        return changes
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _version_key(version: str) -> tuple:
    """Best-effort numeric version key for upgrade/downgrade comparison."""
    parts = []
    for chunk in version.strip().lstrip("v=<>~^ ").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)
