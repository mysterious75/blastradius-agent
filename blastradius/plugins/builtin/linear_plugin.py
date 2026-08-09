"""Linear plugin — create a Linear issue on finding (LINEAR_API_KEY)."""

import json
import os
from urllib import request as urllib_request

from blastradius.plugins.base import BasePlugin

_MUTATION = """
mutation IssueCreate($title: String!, $description: String!) {
  issueCreate(input: { title: $title, description: $description }) {
    issue { id }
  }
}
"""


def _graphql(query: str, variables: dict, token: str) -> None:
    req = urllib_request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps({"query": query, "variables": variables}).encode("utf-8"),
        headers={"Authorization": token, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(req, timeout=15):
        pass


class LinearPlugin(BasePlugin):
    name = "linear"
    version = "1.0.0"

    def on_finding(self, finding) -> None:
        if not os.getenv("LINEAR_API_KEY"):
            return  # graceful: not configured
        _graphql(
            _MUTATION,
            {
                "title": f"BlastRadius: {finding.vuln_type.upper()} in {finding.file}",
                "description": f"File: {finding.file}:{finding.line}\n{finding.evidence}",
            },
            os.getenv("LINEAR_API_KEY"),
        )
