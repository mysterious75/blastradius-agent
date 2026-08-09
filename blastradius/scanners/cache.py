"""ScanCache — file-content -> findings cache (sqlite, 7-day TTL, stdlib only)."""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from blastradius.hunter.scanner import Finding

TTL_DAYS = 7


def _cache_file() -> Path:
    home = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home())))
    return home / ".blastradius" / "scan_cache.db"


class ScanCache:
    """Caches per-file scan findings keyed by content SHA256."""

    def __init__(self, path=None, ttl_days: int = TTL_DAYS):
        self.path = Path(path) if path else _cache_file()
        self.ttl = timedelta(days=ttl_days)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS file_cache ("
                "hash TEXT PRIMARY KEY, findings TEXT, scanned_at TEXT)"
            )

    @staticmethod
    def hash_file(path) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @staticmethod
    def hash_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {
            "file": f.file, "line": f.line, "vuln_type": f.vuln_type,
            "payload": f.payload, "confidence": f.confidence,
            "evidence": f.evidence, "severity": f.severity, "cwe": f.cwe,
            "description": f.description, "remediation": f.remediation,
        }

    @staticmethod
    def _finding_from_dict(d: dict) -> Finding:
        return Finding(
            file=d.get("file", ""), line=d.get("line", 0),
            vuln_type=d.get("vuln_type", ""), payload=d.get("payload", ""),
            confidence=d.get("confidence", 0.0), evidence=d.get("evidence", ""),
            severity=d.get("severity", ""), cwe=d.get("cwe", ""),
            description=d.get("description", ""), remediation=d.get("remediation", ""),
        )

    # ------------------------------------------------------------------
    # Cache access
    # ------------------------------------------------------------------

    def get_cached(self, path) -> Optional[List[Finding]]:
        """Cached findings for a file, or None when stale/missing."""
        try:
            fingerprint = self.hash_file(path)
        except OSError:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT findings, scanned_at FROM file_cache WHERE hash = ?", (fingerprint,)
            ).fetchone()
        if not row:
            return None
        try:
            scanned = datetime.fromisoformat(row["scanned_at"])
        except ValueError:
            return None
        if datetime.now() - scanned > self.ttl:
            return None
        try:
            return [self._finding_from_dict(d) for d in json.loads(row["findings"])]
        except (json.JSONDecodeError, TypeError):
            return None

    def put(self, path, findings: List[Finding]) -> None:
        try:
            fingerprint = self.hash_file(path)
        except OSError:
            return
        data = json.dumps([self._finding_to_dict(f) for f in findings])
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_cache (hash, findings, scanned_at) VALUES (?,?,?)",
                (fingerprint, data, datetime.now().isoformat(timespec="seconds")),
            )

    # ------------------------------------------------------------------
    # Stats / clear
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM file_cache").fetchone()["c"]
        return {"cached_files": total, "db": str(self.path)}

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM file_cache")
