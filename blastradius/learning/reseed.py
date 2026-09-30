"""Reseed log — unproven candidates become seeds for deeper future runs.

PageBreak's lesson: deterministic validation is the gold standard, but the
findings validators *cannot* prove must not be thrown away. They are:

1. **seeds** — prioritized inputs for the next, deeper scan of the same target
   (e.g. run the new validator first on exactly these files/checks);
2. **gap signals** — vuln types that are *never* proven point at missing
   validator capability (``validator_gap_report``), guiding what to build next.

Storage is JSONL beside :mod:`blastradius.learning.improver` outcomes
(``~/.blastradius/reseed.jsonl``, honouring ``BLASTRADIUS_HOME``). Stdlib
only; fully offline-testable.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def _data_dir() -> Path:
    path = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home()))) / ".blastradius"
    path.mkdir(parents=True, exist_ok=True)
    return path


class ReseedLog:
    """Record unproven candidates; serve them back as prioritized seeds."""

    def __init__(self, data_dir: Optional[str] = None, max_entries: int = 500):
        self.data_dir = Path(data_dir) if data_dir else _data_dir()
        self.max_entries = max_entries
        self.log_file = self.data_dir / "reseed.jsonl"

    # ------------------------------------------------------------------
    def record(
        self,
        target: str,
        vuln_type: str,
        file: str = "",
        line: int = 0,
        confidence: float = 0.0,
        reason: str = "",
    ) -> None:
        """Append one unproven candidate seed."""
        entry = {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": target,
            "vuln_type": vuln_type,
            "file": file,
            "line": line,
            "confidence": confidence,
            "reason": reason or "unproven",
        }
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        self._trim()

    def _trim(self) -> None:
        try:
            lines = self.log_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if len(lines) > self.max_entries:
            self.log_file.write_text("\n".join(lines[-self.max_entries :]) + "\n", encoding="utf-8")

    # ------------------------------------------------------------------
    def seeds_for(self, target: str, vuln_type: Optional[str] = None) -> List[Dict]:
        """Prioritized seeds for a target (optionally one vuln type).

        Highest confidence first; each entry carries file/line/check to aim the
        next scan at.
        """
        out = []
        try:
            lines = self.log_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return out
        for raw in lines:
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if entry.get("target") != target:
                continue
            if vuln_type is not None and entry.get("vuln_type") != vuln_type:
                continue
            out.append(entry)
        out.sort(key=lambda e: float(e.get("confidence", 0.0)), reverse=True)
        return out

    def validator_gap_report(self) -> List[Dict]:
        """Vuln types ranked by unproven-candidate count (validator backlog)."""
        counts: Counter = Counter()
        try:
            lines = self.log_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for raw in lines:
            try:
                counts[json.loads(raw).get("vuln_type", "?")] += 1
            except ValueError:
                continue
        return [
            {"vuln_type": vt, "unproven": n, "suggestion": f"validator needed: {vt}"}
            for vt, n in counts.most_common()
        ]
