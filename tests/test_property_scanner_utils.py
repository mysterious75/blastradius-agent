"""Property-based tests for scanner text helpers and path normalisation."""

import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from blastradius.hunter.scanner import Finding
from blastradius.hunter.scanner import _code_only as hunter_code_only
from blastradius.scanners._util import code_only, first_arg_var, strip_literals
from scripts.pr_scan import _normalise_file

_TEXT = st.text(max_size=120)
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
_SEGMENT = st.from_regex(r"[A-Za-z0-9_-]{1,12}", fullmatch=True)


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_strip_literals_preserves_length(line: str) -> None:
    assert len(strip_literals(line)) == len(line)


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_strip_literals_is_idempotent(line: str) -> None:
    once = strip_literals(line)
    assert strip_literals(once) == once


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_code_only_is_a_prefix_of_masked_line(line: str) -> None:
    masked = strip_literals(line)
    assert masked.startswith(code_only(line))


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_hunter_code_only_preserves_length(line: str) -> None:
    assert len(hunter_code_only(line)) == len(line)


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_hunter_code_only_is_idempotent(line: str) -> None:
    once = hunter_code_only(line)
    assert hunter_code_only(once) == once


@settings(max_examples=200, deadline=None)
@given(_TEXT)
def test_first_arg_var_is_empty_or_identifier(line: str) -> None:
    value = first_arg_var(line)
    assert value == "" or _IDENT.match(value) is not None


@settings(max_examples=100, deadline=None)
@given(st.lists(_SEGMENT, min_size=1, max_size=3))
def test_normalise_file_stays_repo_relative(parts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as root_dir:
        root = Path(root_dir)
        finding = Finding(
            file=str(root.joinpath(*parts)),
            line=1,
            vuln_type="sqli",
            payload="x",
            confidence=1.0,
        )
        result = _normalise_file(finding, str(root))
    assert result == Path(*parts).as_posix()
    assert "\\" not in result
    assert not result.startswith("../")


def test_normalise_file_outside_repo_never_returns_backslashes(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside" / "app.py"
    finding = Finding(
        file=str(outside),
        line=1,
        vuln_type="sqli",
        payload="x",
        confidence=1.0,
    )
    assert "\\" not in _normalise_file(finding, str(tmp_path))
