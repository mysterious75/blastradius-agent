"""Scheduler tests — stdlib fallback path, all network mocked."""

import time

import pytest

from blastradius.scheduler.cron import HuntScheduler
from blastradius.scheduler.__main__ import main as sched_main


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("HUNT_SCHEDULE", raising=False)
    monkeypatch.delenv("HUNT_MAX_TARGETS", raising=False)


def test_disabled_by_default():
    s = HuntScheduler()
    assert s.schedule() == {}
    assert s.start() is False


def test_daily_schedule(monkeypatch):
    monkeypatch.setenv("HUNT_SCHEDULE", "daily")
    s = HuntScheduler()
    jobs = s.schedule()
    assert set(jobs) == {"daily_hunt", "hourly_check"}
    assert jobs["daily_hunt"]["strategy"] == "github"
    assert jobs["daily_hunt"]["targets"] == 10  # HUNT_MAX_TARGETS default


def test_weekly_schedule(monkeypatch):
    monkeypatch.setenv("HUNT_SCHEDULE", "weekly")
    s = HuntScheduler()
    jobs = s.schedule()
    assert "weekly_deep" in jobs
    assert jobs["weekly_deep"]["strategy"] == "all"
    assert jobs["weekly_deep"]["targets"] == 50


def test_stdlib_loop_runs_job(monkeypatch):
    monkeypatch.setenv("HUNT_SCHEDULE", "daily")
    calls = []
    s = HuntScheduler(tick=0.1)
    s.auto_hunt = lambda strategy, max_targets, min_stars: calls.append(strategy)
    assert s.start() is True  # stdlib fallback (APScheduler not installed)
    time.sleep(0.5)
    s.stop()
    assert calls  # daily_hunt fires immediately on the first tick
    assert "github" in calls


def test_run_now(monkeypatch):
    calls = []
    s = HuntScheduler()
    s.auto_hunt = lambda strategy, max_targets, min_stars: calls.append((strategy, max_targets))
    s.run_now("github", max_targets=3)
    assert calls == [("github", 3)]


def test_hourly_check_counts_vulns(monkeypatch):
    s = HuntScheduler()
    monkeypatch.setattr(
        "blastradius.recon.dorker.DorkEngine.pypi_web_packages",
        lambda self, limit=500, use_cache=True: [
            {"package": "flask-awesome", "url": "https://github.com/org/x"},
            {"package": "django-kit", "url": "https://github.com/org/y"},
        ],
    )
    monkeypatch.setattr(
        HuntScheduler, "_osv_query",
        lambda self, package: [{"id": "GHSA-1"}, {"id": "GHSA-2"}] if package == "flask-awesome" else [],
    )
    assert s.run_hourly_check() == 2


def test_status_shows_next_runs(monkeypatch):
    monkeypatch.setenv("HUNT_SCHEDULE", "daily")
    s = HuntScheduler()
    s.schedule()
    status = s.status()
    assert "daily_hunt" in status and "hourly_check" in status
    assert status["daily_hunt"]  # non-empty ISO timestamp


def test_cli_status(monkeypatch, capsys):
    monkeypatch.setenv("HUNT_SCHEDULE", "daily")
    assert sched_main(["status"]) == 0
    out = capsys.readouterr().out
    assert "daily_hunt" in out and "hourly_check" in out


def test_cli_status_disabled(capsys):
    assert sched_main(["status"]) == 0
    assert "disabled" in capsys.readouterr().out


def test_cli_run_now(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "blastradius.scheduler.cron.HuntScheduler._hunt",
        lambda self, strategy, max_targets: calls.append((strategy, max_targets)),
    )
    assert sched_main(["run-now", "--strategy", "github", "--max-targets", "7"]) == 0
    assert calls == [("github", 7)]
