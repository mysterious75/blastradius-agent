"""Reseed log tests — offline, tmp data dir, no network."""

from blastradius.learning.reseed import ReseedLog


def _log(tmp_path):
    return ReseedLog(data_dir=str(tmp_path))


def test_record_and_retrieve_seeds(tmp_path):
    log = _log(tmp_path)
    log.record("repo-A", "xxe", file="parse.py", line=9, confidence=0.8)
    log.record("repo-A", "sqli", file="app.py", line=4, confidence=0.95)
    log.record("repo-B", "xxe", file="other.py", line=1, confidence=0.9)
    seeds = log.seeds_for("repo-A")
    assert [s["vuln_type"] for s in seeds] == ["sqli", "xxe"]  # confidence order
    assert seeds[0]["file"] == "app.py"


def test_seeds_filter_by_type(tmp_path):
    log = _log(tmp_path)
    log.record("repo-A", "xxe", confidence=0.8)
    log.record("repo-A", "sqli", confidence=0.9)
    assert [s["vuln_type"] for s in log.seeds_for("repo-A", vuln_type="xxe")] == ["xxe"]


def test_empty_log(tmp_path):
    log = _log(tmp_path)
    assert log.seeds_for("nothing") == []
    assert log.validator_gap_report() == []


def test_gap_report_ranking(tmp_path):
    log = _log(tmp_path)
    for _ in range(3):
        log.record("t", "xxe")
    log.record("t", "sqli")
    report = log.validator_gap_report()
    assert report[0] == {"vuln_type": "xxe", "unproven": 3, "suggestion": "validator needed: xxe"}
    assert report[1]["vuln_type"] == "sqli"


def test_trim_bounds_file(tmp_path):
    log = ReseedLog(data_dir=str(tmp_path), max_entries=5)
    for i in range(9):
        log.record("t", "x", line=i)
    lines = (tmp_path / "reseed.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    assert log.seeds_for("t")[-1]["line"] == 8


def test_malformed_lines_skipped(tmp_path):
    (tmp_path / "reseed.jsonl").write_text(
        '{"bad json\n{"target":"t","vuln_type":"x"}\n', encoding="utf-8"
    )
    log = _log(tmp_path)
    assert len(log.seeds_for("t")) == 1
