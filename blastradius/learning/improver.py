"""SelfImprover — learns from scan outcomes to reduce false positives.

- record_outcome() appends to ~/.blastradius/outcomes.jsonl
- analyze_patterns() computes FP rates per vuln type, always-FP file patterns,
  and payload success
- update_rules() writes ~/.blastradius/learned_rules.json consumed by the
  scanner (confidence thresholds, skip patterns, payload weights)
- weekly_report() summarizes what changed

Zero dependencies (stdlib json/jsonl). Data dir honors BLASTRADIUS_HOME.
"""

import fnmatch
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

BASE_CONFIDENCE = 0.7
MAX_HISTORY = 100


def _data_dir() -> Path:
    path = Path(os.getenv("BLASTRADIUS_HOME", str(Path.home()))) / ".blastradius"
    path.mkdir(parents=True, exist_ok=True)
    return path


class SelfImprover:
    """Record outcomes, analyze patterns, and write scanner rules."""

    def __init__(self, data_dir: Optional[str] = None, max_history: int = MAX_HISTORY):
        self.data_dir = Path(data_dir) if data_dir else _data_dir()
        self.max_history = max_history
        self.outcomes_file = self.data_dir / "outcomes.jsonl"
        self.rules_file = self.data_dir / "learned_rules.json"

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_outcome(self, finding, was_fp: bool, sandbox_result: str = "",
                       patch_confidence: float = 0.0) -> None:
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "vuln_type": finding.vuln_type,
            "file": finding.file,
            "payload": finding.payload,
            "was_fp": bool(was_fp),
            "sandbox": sandbox_result,
            "patch_confidence": patch_confidence,
        }
        with open(self.outcomes_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        self._trim()

    def _trim(self) -> None:
        lines = self.read_outcomes(limit=self.max_history * 2)
        if len(lines) > self.max_history:
            keep = lines[-self.max_history:]
            with open(self.outcomes_file, "w", encoding="utf-8") as fh:
                for line in keep:
                    fh.write(json.dumps(line) + "\n")

    def read_outcomes(self, limit: Optional[int] = None) -> List[Dict]:
        if not self.outcomes_file.is_file():
            return []
        lines = []
        with open(self.outcomes_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return lines if limit is None else lines[-limit:]

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze_patterns(self) -> Dict:
        """Compute FP rates, always-FP file patterns, and payload success."""
        outcomes = self.read_outcomes(limit=self.max_history)
        if not outcomes:
            return {"sample_size": 0}

        by_type: Dict[str, List[Dict]] = {}
        for o in outcomes:
            by_type.setdefault(o.get("vuln_type", "?"), []).append(o)

        fp_rates = {}
        for vuln_type, items in by_type.items():
            fp = sum(1 for i in items if i.get("was_fp"))
            fp_rates[vuln_type] = round(fp / len(items), 3)

        file_fp, file_total = Counter(), Counter()
        for o in outcomes:
            name = Path(o.get("file", "?")).name
            file_total[name] += 1
            if o.get("was_fp"):
                file_fp[name] += 1
        # a file is "always FP" when >= 3 outcomes and every one was FP
        skip_patterns = sorted(
            name for name, total in file_total.items()
            if total >= 3 and file_fp[name] == total
        )

        payload_success = Counter()
        for o in outcomes:
            if o.get("sandbox") == "CONFIRMED_EXPLOITABLE" and not o.get("was_fp"):
                token = (o.get("payload") or "").strip().split()[:2]
                if token:
                    payload_success[" ".join(token)] += 1

        return {
            "sample_size": len(outcomes),
            "fp_rates": fp_rates,
            "skip_patterns": skip_patterns,
            "payload_success": dict(payload_success.most_common(5)),
        }

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def update_rules(self, analysis: Optional[Dict] = None) -> Dict:
        analysis = analysis or self.analyze_patterns()
        thresholds = {}
        for vuln_type, rate in analysis.get("fp_rates", {}).items():
            # raise the bar as the FP rate grows: 0.7 + 0.5 * FP-rate, capped at 0.95
            thresholds[vuln_type] = round(min(0.95, BASE_CONFIDENCE + rate * 0.5), 2)
        rules = {
            "confidence_thresholds": thresholds,
            "skip_patterns": analysis.get("skip_patterns", []),
            "payload_weights": {},
        }
        for token, hits in analysis.get("payload_success", {}).items():
            if hits >= 2:  # only boost proven payloads
                rules["payload_weights"][token] = 1.2
        self.rules_file.write_text(json.dumps(rules, indent=2), encoding="utf-8")
        return rules

    def load_rules(self) -> Dict:
        try:
            if self.rules_file.is_file():
                return json.loads(self.rules_file.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def apply_rules(self) -> Dict:
        """Return the learned rules (what the scanner will honor on next run)."""
        return self.load_rules()

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def weekly_report(self) -> str:
        analysis = self.analyze_patterns()
        rules = self.load_rules()
        thresholds = rules.get("confidence_thresholds", {})
        lines = [
            "# BlastRadius Learning Report",
            f"- Sample: {analysis.get('sample_size', 0)} outcome(s)",
        ]
        for vuln_type, rate in analysis.get("fp_rates", {}).items():
            raised = thresholds.get(vuln_type, BASE_CONFIDENCE)
            lines.append(f"- {vuln_type.upper()} FP rate: {rate:.0%} → threshold raised to {raised}")
        for pattern in analysis.get("skip_patterns", []):
            lines.append(f"- Skipping {pattern} (100% FP in last {MAX_HISTORY} scans)")
        for token, hits in analysis.get("payload_success", {}).items():
            lines.append(f"- Payload '{token}' confirmed {hits}× → weight 1.2")
        return "\n".join(lines)
