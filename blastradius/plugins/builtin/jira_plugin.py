"""Jira plugin — file a ticket when a finding is produced (JIRA_URL/JIRA_TOKEN)."""

import json
import os
from urllib import request as urllib_request

from blastradius.plugins.base import BasePlugin


def _post(url: str, payload: dict, token: str) -> None:
    req = urllib_request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(req, timeout=15):
        pass


class JiraPlugin(BasePlugin):
    name = "jira"
    version = "1.0.0"

    def on_finding(self, finding) -> None:
        if not (os.getenv("JIRA_URL") and os.getenv("JIRA_TOKEN")):
            return  # graceful: not configured
        url = os.getenv("JIRA_URL").rstrip("/") + "/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": os.getenv("JIRA_PROJECT", "SEC")},
                "summary": f"BlastRadius: {finding.vuln_type.upper()} in {finding.file}",
                "issuetype": {"name": "Bug"},
                "description": f"File: {finding.file}:{finding.line}\nEvidence:\n{finding.evidence}",
            }
        }
        _post(url, payload, os.getenv("JIRA_TOKEN"))
