"""Many-users-at-once test for the static scanner.

The scanner is called from parallel PR workers and the API. Its new
function-index cache is thread-local and keyed by object identity, so two
repos scanned concurrently must never see each other's lines, findings, or
cache state.
"""

import concurrent.futures

import pytest

from blastradius.hunter.scanner import CVEHunter


def _signature(findings):
    return sorted((str(f.file), f.line, f.vuln_type) for f in findings)


def _build_repo(root, prefix):
    for i in range(12):
        (root / f"{prefix}_{i}.py").write_text(
            "def handler(request):\n"
            "    name = request.args.get('name')\n"
            f'    q = "SELECT * FROM {prefix} WHERE name = \'" + name + "\'"\n'
            "    return q\n",
            encoding="utf-8",
        )
    (root / f"{prefix}_safe.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")


@pytest.mark.integration
@pytest.mark.adversarial
def test_concurrent_scans_are_isolated_and_deterministic(tmp_path):
    repos = [tmp_path / "alpha", tmp_path / "beta"]
    for repo, prefix in zip(repos, ("alpha", "beta")):
        repo.mkdir()
        _build_repo(repo, prefix)

    serial = {}
    for repo in repos:
        serial[repo.name] = _signature(CVEHunter().scan_repo(str(repo)))
        assert len(serial[repo.name]) == 12

    def one(index):
        repo = repos[index % len(repos)]
        return repo.name, _signature(CVEHunter().scan_repo(str(repo)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, range(24)))

    for name, signature in results:
        assert signature == serial[name]
        foreign = "beta" if name == "alpha" else "alpha"
        assert all(foreign not in path for path, _line, _kind in signature)


@pytest.mark.integration
@pytest.mark.adversarial
def test_same_repo_concurrent_scans_are_stable(tmp_path):
    repo = tmp_path / "one"
    repo.mkdir()
    _build_repo(repo, "solo")
    baseline = _signature(CVEHunter().scan_repo(str(repo)))

    def one(_):
        return _signature(CVEHunter().scan_repo(str(repo)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, range(16)))
    assert all(result == baseline for result in results)
