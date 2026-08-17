"""DisclosureReport — markdown responsible-disclosure report for a finding.

The report includes the vulnerability description, affected file + line, a
PoC, the sandbox validation result, a suggested patch, and a CVSS estimate.
"""

import datetime
from pathlib import Path
from typing import Optional

from blastradius.hunter.scanner import Finding, VULN_META, reconstruct_target_code
from blastradius.tools.sandbox_tool import run_exploit_sandbox


class DisclosureReport:
    """Generate and persist markdown disclosure reports for findings."""

    def generate_report(
        self,
        finding: Finding,
        repo_name: str = "unknown",
        sandbox_result: Optional[str] = None,
    ) -> str:
        """Return the markdown report for ``finding``.

        Args:
            finding: The Finding to report.
            repo_name: Repo name used in the title (and report filename).
            sandbox_result: Pre-computed sandbox output; when None it is
                computed by running the reconstructed PoC in the sandbox.
        """
        if sandbox_result is None:
            sandbox_result = self._run_sandbox(finding)

        date = datetime.date.today().isoformat()
        f = finding
        verdict = sandbox_result.splitlines()[0] if sandbox_result else "NOT RUN"

        return f"""# Vulnerability Disclosure: {f.vuln_type.upper()} in {repo_name}

- **Date:** {date}
- **Severity:** {f.severity} | **CVSS estimate:** {VULN_META.get(f.vuln_type, {}).get("cvss", "n/a")} | **CWE:** {f.cwe}
- **Affected file:** `{f.file}` line {f.line}
- **Confidence:** {f.confidence}

## Vulnerability description

{f.description}

## Proof of Concept

```text
{f.payload}
```

Code context:

```text
{f.context}
```

## Sandbox validation

{verdict}

```
{sandbox_result}
```

> Note: the PoC is reconstructed from the static finding. It proves the
> pattern is exploitable; a live exploit against the real deployment must be
> confirmed manually before any disclosure.

## Suggested patch

{f.remediation}

## Responsible disclosure

Coordinate with the maintainers (security contact / GitHub Security Advisory)
and wait for the fix before public disclosure.
"""

    def save_report(
        self,
        finding: Finding,
        repo_name: str,
        reports_dir: str = "reports",
        sandbox_result: Optional[str] = None,
    ) -> Path:
        """Save the report to ``reports_dir/YYYY-MM-DD_<type>_<repo>_<file>-<line>.md``.

        The file stem + line suffix keeps reports from multiple findings of
        the same type+repo from overwriting each other. Returns the path.
        """
        content = self.generate_report(finding, repo_name, sandbox_result)
        date = datetime.date.today().isoformat()
        stem = Path(finding.file).stem
        path = (
            Path(reports_dir) / f"{date}_{finding.vuln_type}_{repo_name}_{stem}-{finding.line}.md"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def _run_sandbox(finding: Finding) -> str:
        try:
            return run_exploit_sandbox(finding.vuln_type, reconstruct_target_code(finding))
        except Exception as exc:
            return f"SANDBOX_ERROR: {exc}"
