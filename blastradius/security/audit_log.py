"""AuditLogger — append-only JSONL audit log with SHA256 tamper chain.

Every entry stores the hash of the previous entry, so tampering is
detectable. File: ~/.blastradius/audit.jsonl (BLASTRADIUS_HOME aware).
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


def _audit_file() -> Path:
    home = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home())))
    return home / ".blastradius" / "audit.jsonl"


def _canonical(entry: Dict) -> str:
    return json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True)


class AuditLogger:
    """Append-only, tamper-evident event log."""

    def __init__(self, path=None):
        self.path = Path(path) if path else _audit_file()

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _last_hash(self) -> str:
        entries = self.read()
        return entries[-1].get("hash", "0" * 64) if entries else "0" * 64

    def log(self, event: str, **data) -> Dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "event": event,
            **data,
            "prev_hash": self._last_hash(),
        }
        entry["hash"] = hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    # ------------------------------------------------------------------
    # Reading / verification
    # ------------------------------------------------------------------

    def read(self) -> List[Dict]:
        if not self.path.is_file():
            return []
        entries = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def verify(self) -> Tuple[bool, str]:
        """(ok, message) — walks the hash chain and recomputes every hash."""
        entries = self.read()
        prev = "0" * 64
        for idx, entry in enumerate(entries):
            if entry.get("prev_hash") != prev:
                return False, f"chain broken at entry {idx}"
            expected = hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()
            if entry.get("hash") != expected:
                return False, f"hash mismatch at entry {idx}"
            prev = entry["hash"]
        return True, f"{len(entries)} entries verified"
