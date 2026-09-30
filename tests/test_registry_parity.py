"""Registry parity tests — VULN_META, _title(), and docs must agree.

Guards the class of bug where a vuln type exists in one place but not another
(e.g. `secret` was in VULN_META but had no display title).
"""

from pathlib import Path

import blastradius.hunter.scanner as S
from blastradius.hunter.scanner import CVEHunter

REPO = Path(__file__).resolve().parents[1]


def test_every_meta_type_has_title():
    missing = [k for k in S.VULN_META.keys() if CVEHunter._title(k) == k]
    assert missing == [], f"types without display title: {missing}"


def test_title_covers_meta():
    assert len(S.VULN_META) == 18


def test_docs_match_registry():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "18 types" in readme or "18 vuln types" in readme
    agents = (REPO / "AGENTS.md").read_text(encoding="utf-8")
    assert "18 vuln types" in agents


def test_changelog_notes_correction():
    log = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "18" in log
