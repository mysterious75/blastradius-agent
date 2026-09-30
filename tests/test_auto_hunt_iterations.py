"""Same-seed iteration tests for AutoHunt (offline, mocked discovery)."""

from blastradius.recon.auto_hunt import AutoHunt


class FakeDork:
    def __init__(self, targets):
        self.targets = targets
        self.calls = 0

    def find_targets(self, strategy, min_stars=0, limit=200):
        self.calls += 1
        return list(self.targets)


class FakeHunter:
    files_scanned = 1

    def __init__(self, confirmed_per_call=1):
        self.confirmed_per_call = confirmed_per_call
        self.calls = 0

    def clone_repo(self, url):
        return "/tmp/x"

    def scan_repo(self, path):
        self.calls += 1
        return []


def test_iterations_aggregate_runs():
    dork = FakeDork([{"url": "https://github.com/a/b", "repo": "a/b", "stars": 1}])
    hunt = AutoHunt(dork_engine=dork, hunter=FakeHunter())
    rows = hunt.run("github", max_targets=5, iterations=3, seed=7)
    assert dork.calls == 3
    assert rows[0]["runs"] == 3


def test_single_iteration_default():
    dork = FakeDork([{"url": "https://github.com/a/b", "repo": "a/b", "stars": 1}])
    hunt = AutoHunt(dork_engine=dork, hunter=FakeHunter())
    rows = hunt.run("github", max_targets=5)
    assert rows[0]["runs"] == 1


def test_iterations_zero_or_negative_clamped():
    dork = FakeDork([{"url": "https://github.com/a/b", "repo": "a/b", "stars": 1}])
    hunt = AutoHunt(dork_engine=dork, hunter=FakeHunter())
    hunt.run("github", max_targets=5, iterations=0)
    assert dork.calls == 1


def test_same_seed_deterministic_order():
    dork = FakeDork([{"url": "https://github.com/a/b", "repo": "a/b", "stars": 1}])
    hunt = AutoHunt(dork_engine=dork, hunter=FakeHunter())
    r1 = hunt.run("github", max_targets=5, iterations=2, seed=42)
    r2 = hunt.run("github", max_targets=5, iterations=2, seed=42)
    assert [r["repo"] for r in r1] == [r["repo"] for r in r2]
