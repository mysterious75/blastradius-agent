"""SQLiteDB — persistent storage for scans, findings, patches, reports, provider usage.

Zero external dependencies (stdlib sqlite3). DB file: ~/.blastradius/blastradius.db
(override with BLASTRADIUS_DB or BLASTRADIUS_HOME).
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    finished_at TEXT,
    files_scanned INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    file TEXT,
    line INTEGER,
    vuln_type TEXT,
    confidence REAL,
    payload TEXT,
    severity TEXT,
    description TEXT,
    remediation TEXT,
    cwe TEXT
);
CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    original TEXT,
    patched TEXT,
    diff TEXT,
    confidence REAL,
    attempts INTEGER,
    needs_human INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    path TEXT,
    created_at TEXT,
    disclosed_at TEXT
);
CREATE TABLE IF NOT EXISTS providers_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT,
    model TEXT,
    tokens_used INTEGER DEFAULT 0,
    cost_est REAL DEFAULT 0.0,
    timestamp TEXT
);
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT UNIQUE,
    finding_id INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    count INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS cve_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    cve_id TEXT,
    disclosed_at TEXT,
    fixed_at TEXT,
    bounty_usd REAL DEFAULT 0
);
"""


def default_db_path() -> Path:
    override = os.getenv("BLASTRADIUS_DB")
    if override:
        return Path(override)
    home = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home())))
    return home / ".blastradius" / "blastradius.db"


class SQLiteDB:
    """Persistent store backed by SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @staticmethod
    def _row(row: Optional[sqlite3.Row]) -> Optional[Dict]:
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def save_scan(self, target: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, status, started_at) VALUES (?, ?, ?)",
                (target, "pending", datetime.now().isoformat(timespec="seconds")),
            )
            return cur.lastrowid

    def update_scan(
        self,
        scan_id: int,
        status: Optional[str] = None,
        files_scanned: Optional[int] = None,
        finished_at: Optional[str] = None,
    ) -> None:
        sets, vals = [], []
        if status is not None:
            sets.append("status = ?")
            vals.append(status)
        if files_scanned is not None:
            sets.append("files_scanned = ?")
            vals.append(files_scanned)
        if finished_at is not None:
            sets.append("finished_at = ?")
            vals.append(finished_at)
        if not sets:
            return
        vals.append(scan_id)
        with self._connect() as conn:
            conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            return self._row(
                conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            )

    def get_scans(self, limit: int = 50) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def save_finding(self, scan_id: int, finding) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO findings (scan_id, file, line, vuln_type, confidence, payload, "
                "severity, description, remediation, cwe) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id,
                    finding.file,
                    finding.line,
                    finding.vuln_type,
                    finding.confidence,
                    finding.payload,
                    finding.severity,
                    finding.description,
                    finding.remediation,
                    finding.cwe,
                ),
            )
            return cur.lastrowid

    def get_findings(self, scan_id: int) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_all_findings(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Patches
    # ------------------------------------------------------------------

    def save_patch(
        self, finding_id: int, patch, attempts: int, needs_human: bool, confidence: float = 0.0
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO patches (finding_id, original, patched, diff, confidence, "
                "attempts, needs_human) VALUES (?,?,?,?,?,?,?)",
                (
                    finding_id,
                    patch.original_code,
                    patch.patched_code,
                    patch.diff,
                    confidence,
                    attempts,
                    int(needs_human),
                ),
            )
            return cur.lastrowid

    def get_patch(self, finding_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            return self._row(
                conn.execute(
                    "SELECT * FROM patches WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
                    (finding_id,),
                ).fetchone()
            )

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def save_report(self, finding_id: int, path: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO reports (finding_id, path, created_at) VALUES (?, ?, ?)",
                (finding_id, path, datetime.now().isoformat(timespec="seconds")),
            )
            return cur.lastrowid

    def get_reports(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Provider usage
    # ------------------------------------------------------------------

    def log_provider_usage(
        self, provider: str, model: str, tokens: int = 0, cost: float = 0.0
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO providers_log (provider, model, tokens_used, cost_est, timestamp) "
                "VALUES (?,?,?,?,?)",
                (
                    provider,
                    model,
                    int(tokens),
                    float(cost),
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
            return cur.lastrowid

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
            done = conn.execute("SELECT COUNT(*) c FROM scans WHERE status = 'done'").fetchone()[
                "c"
            ]
            confirmed = conn.execute("SELECT COUNT(*) c FROM patches").fetchone()["c"]
            patches = confirmed
            findings = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
            return {
                "total_scans": total,
                "confirmed": confirmed,
                "patches": patches,
                "findings": findings,
                "success_rate": round(done / total * 100, 1) if total else 0.0,
            }

    def clear(self) -> None:
        with self._connect() as conn:
            for table in ("scans", "findings", "patches", "reports", "providers_log"):
                conn.execute(f"DELETE FROM {table}")
