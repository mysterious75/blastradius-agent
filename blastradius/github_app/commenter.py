"""PRCommenter — posts BlastRadius findings as GitHub PR comments.

Posts via the GitHub REST API when a GITHUB_TOKEN is available; otherwise it
runs in dry-run mode and returns the comment body (used in tests and local
development).
"""

import json
import os
import urllib.request
from typing import Optional

_VULN_LABELS = {"sqli": "SQLi", "xss": "XSS", "ssrf": "SSRF"}


def _label(vuln_type: str) -> str:
    return _VULN_LABELS.get(vuln_type, vuln_type.upper())


def _confidence_percent(confidence: float) -> int:
    if confidence <= 1.0:
        return int(round(confidence * 100))
    return int(round(confidence))


class PRCommenter:
    """Build and post BlastRadius finding comments on pull requests."""

    def __init__(self, token: Optional[str] = None, api_base: str = "https://api.github.com"):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = api_base

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_comment(
        self,
        finding,
        patch_result=None,
        exploit_output: str = "",
    ) -> str:
        """Build the markdown comment for a finding (+ optional patch result)."""
        if patch_result is not None and not patch_result.needs_human:
            status = "CONFIRMED_EXPLOITABLE → PATCH_GENERATED"
        elif patch_result is not None:
            status = "CONFIRMED_EXPLOITABLE → PATCH_NEEDS_REVIEW"
        else:
            status = "CONFIRMED_EXPLOITABLE"

        diff = (
            patch_result.patch.diff
            if patch_result is not None and patch_result.patch
            else "(no patch available)"
        )
        proof = exploit_output or finding.evidence or finding.payload or "(no exploit output)"

        return f"""## 🔴 BlastRadius Security Finding

**Type:** {_label(finding.vuln_type)} | **Confidence:** {_confidence_percent(finding.confidence)}% | **File:** {finding.file}:{finding.line}
**Status:** {status}

<details><summary>Patch Diff</summary>

```diff
{diff}
```

</details>

<details><summary>Exploit Proof</summary>

```
{proof}
```

</details>

⚠️ Awaiting human review before merge.
"""

    def post_finding_comment(
        self,
        repo: str,
        pr_number: int,
        finding,
        patch_result=None,
        exploit_output: str = "",
    ) -> str:
        """Post the comment on the PR; returns the comment body.

        With no GITHUB_TOKEN this is a dry run — the body is returned without
        any network call.
        """
        body = self.build_comment(finding, patch_result, exploit_output)
        if not self.token:
            return body

        url = f"{self.api_base}/repos/{repo}/issues/{pr_number}/comments"
        req = urllib.request.Request(
            url,
            data=json.dumps({"body": body}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "BlastRadius",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        return body
