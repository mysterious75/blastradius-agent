"""HuntScheduler — periodic auto-hunt jobs.

Uses APScheduler when installed (optional dep), otherwise a pure-stdlib
thread loop. Config via env:

    HUNT_SCHEDULE=daily|weekly|disabled   (default: disabled)
    HUNT_MAX_TARGETS=10

Jobs:
    daily_hunt    every 24h  → auto-hunt github strategy, top N
    weekly_deep   every 7d   → auto-hunt all strategy, top 50
    hourly_check  every 1h   → check PyPI deps against OSV known-vulns
"""

import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional


class HuntScheduler:
    """Schedule and run periodic auto-hunt jobs."""

    def __init__(self, auto_hunt: Optional[Callable] = None, tick: float = 30.0):
        self.max_targets = int(os.getenv("HUNT_MAX_TARGETS", "10"))
        self.tick = tick
        self._jobs: Dict[str, dict] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._aps = None
        self.auto_hunt = auto_hunt

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def schedule(self) -> Dict[str, dict]:
        """Build the job table from HUNT_SCHEDULE; returns {name: job}."""
        self._jobs = {}
        mode = os.getenv("HUNT_SCHEDULE", "disabled").lower()
        if mode == "disabled":
            return self._jobs
        now = datetime.now()
        if mode == "daily":
            self._jobs["daily_hunt"] = {
                "interval": timedelta(hours=24), "next": now, "strategy": "github",
                "targets": self.max_targets,
            }
        elif mode == "weekly":
            self._jobs["weekly_deep"] = {
                "interval": timedelta(days=7), "next": now, "strategy": "all",
                "targets": 50,
            }
        self._jobs["hourly_check"] = {
            "interval": timedelta(hours=1), "next": now,
        }
        return self._jobs

    def start(self) -> bool:
        """Start the scheduler; returns False when disabled."""
        if not self.schedule():
            return False
        try:
            return self._start_apscheduler()
        except ImportError:
            return self._start_stdlib()

    def stop(self) -> None:
        self._running = False
        if self._aps is not None:
            try:
                self._aps.shutdown(wait=False)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # APScheduler (preferred when installed)
    # ------------------------------------------------------------------

    def _start_apscheduler(self) -> bool:
        from apscheduler.schedulers.background import BackgroundScheduler

        self._aps = BackgroundScheduler()
        for name, job in self._jobs.items():
            self._aps.add_job(
                lambda n=name: self._run_job(n),
                "interval",
                seconds=int(job["interval"].total_seconds()),
                id=name,
            )
        self._aps.start()
        self._running = True
        return True

    # ------------------------------------------------------------------
    # Stdlib fallback (no APScheduler)
    # ------------------------------------------------------------------

    def _start_stdlib(self) -> bool:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def _loop(self) -> None:
        while self._running:
            now = datetime.now()
            for name, job in self._jobs.items():
                if job.get("next", now) <= now:
                    try:
                        self._run_job(name)
                    except Exception:
                        pass
                    job["next"] = now + job["interval"]
            time.sleep(self.tick)

    # ------------------------------------------------------------------
    # Job execution
    # ------------------------------------------------------------------

    def _run_job(self, name: str) -> None:
        job = self._jobs.get(name)
        if job is None:
            return
        if name == "daily_hunt":
            self._hunt(job["strategy"], job["targets"])
        elif name == "weekly_deep":
            self._hunt(job["strategy"], job["targets"])
        elif name == "hourly_check":
            self.run_hourly_check()

    def _hunt(self, strategy: str, max_targets: int) -> None:
        if self.auto_hunt is not None:
            self.auto_hunt(strategy, max_targets=max_targets, min_stars=0)
            return
        from blastradius.recon.auto_hunt import AutoHunt

        AutoHunt().run(strategy, max_targets=max_targets, min_stars=0)

    def run_hourly_check(self) -> int:
        """Check PyPI deps for known vulnerabilities via the OSV API."""
        from blastradius.recon.dorker import DorkEngine

        packages = DorkEngine().pypi_web_packages(limit=self.max_targets)
        found = 0
        for pkg in packages[:5]:
            try:
                found += len(self._osv_query(pkg["package"]))
            except Exception:
                continue
        return found

    @staticmethod
    def _osv_query(package: str) -> list:
        body = json.dumps({"package": {"name": package, "ecosystem": "PyPI"}}).encode("utf-8")
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")).get("vulns", [])

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, str]:
        out = {}
        if self._aps is not None:
            for job in self._aps.get_jobs():
                out[job.id] = str(job.next_run_time or "not scheduled")
        else:
            for name, job in self._jobs.items():
                out[name] = job["next"].isoformat(timespec="seconds")
        return out

    def run_now(self, strategy: str = "github", max_targets: Optional[int] = None) -> None:
        self._hunt(strategy, max_targets or self.max_targets)
