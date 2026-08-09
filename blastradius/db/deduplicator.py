"""Deduplicator — finding fingerprints + CVE tracking (extends SQLiteDB)."""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from blastradius.db.database import SQLiteDB


class Deduplicator:
    """Deduplicate findings and track CVE disclosure state."""

    def __init__(self, db: Optional[SQLiteDB] = None):
        self.db = db or SQLiteDB()

    # ------------------------------------------------------------------
    # Fingerprints
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint(finding, repo: str = "") -> str:
        """SHA256 of (repo, file, line, vuln_type, payload)."""
        key = "|".join([
            repo,
            getattr(finding, "file", ""),
            str(getattr(finding, "line", "")),
            getattr(finding, "vuln_type", ""),
            getattr(finding, "payload", ""),
        ])
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def is_duplicate(self, finding, repo: str = "") -> bool:
        """Register the finding; True when this exact finding was seen before."""
        fp = self.fingerprint(finding, repo)
        now = datetime.now().isoformat(timespec="seconds")
        with self.db._connect() as conn:
            row = conn.execute(
                "SELECT count FROM fingerprints WHERE fingerprint = ?", (fp,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE fingerprints SET count = count + 1, last_seen = ? "
                    "WHERE fingerprint = ?", (now, fp),
                )
                return True
            conn.execute(
                "INSERT INTO fingerprints (fingerprint, finding_id, first_seen, last_seen, count) "
                "VALUES (?,?,?,?,1)", (fp, getattr(finding, "id", 0), now, now),
            )
            return False

    # ------------------------------------------------------------------
    # CVE tracking
    # ------------------------------------------------------------------

    def mark_disclosed(self, finding_id: int, cve_id: str = "", bounty: float = 0.0) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self.db._connect() as conn:
            row = conn.execute(
                "SELECT id FROM cve_tracking WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE cve_tracking SET cve_id = ?, disclosed_at = ?, bounty_usd = ? "
                    "WHERE finding_id = ?", (cve_id, now, float(bounty), finding_id),
                )
            else:
                conn.execute(
                    "INSERT INTO cve_tracking (finding_id, cve_id, disclosed_at, bounty_usd) "
                    "VALUES (?,?,?,?)", (finding_id, cve_id, now, float(bounty)),
                )

    def mark_fixed(self, finding_id: int) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        with self.db._connect() as conn:
            conn.execute(
                "UPDATE cve_tracking SET fixed_at = ? WHERE finding_id = ?",
                (now, finding_id),
            )

    def get_disclosure_status(self, finding_id: int) -> str:
        """pending | submitted | fixed | cve_assigned"""
        with self.db._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cve_tracking WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if not row:
            return "pending"
        if row["fixed_at"]:
            return "fixed"
        if row["cve_id"]:
            return "cve_assigned"
        return "submitted"

    def get_tracking_rows(self) -> List[Dict]:
        """Join cve_tracking with findings for the tracker CLI."""
        with self.db._connect() as conn:
            rows = conn.execute(
                "SELECT t.finding_id, t.cve_id, t.disclosed_at, t.fixed_at, t.bounty_usd, "
                "f.vuln_type, f.file, f.line "
                "FROM cve_tracking t LEFT JOIN findings f ON f.id = t.finding_id "
                "ORDER BY t.disclosed_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        rows = self.get_tracking_rows()
        total = len(rows)
        assigned = sum(1 for r in rows if r.get("cve_id"))
        bounty = sum(float(r.get("bounty_usd") or 0) for r in rows)
        fix_times = []
        for r in rows:
            if r.get("disclosed_at") and r.get("fixed_at"):
                try:
                    start = datetime.fromisoformat(r["disclosed_at"])
                    end = datetime.fromisoformat(r["fixed_at"])
                    fix_times.append((end - start).days)
                except ValueError:
                    continue
        return {
            "total_disclosed": total,
            "assigned_cves": assigned,
            "total_bounty_usd": round(bounty, 2),
            "avg_fix_days": round(sum(fix_times) / len(fix_times), 1) if fix_times else None,
        }
