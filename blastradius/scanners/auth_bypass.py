"""AuthBypassScanner — self-contained authentication-bypass detection.

Sinks (corpus-derived from 300+ real 'Improper Authentication' HackerOne
reports): client-supplied role/admin/privilege, decisions on client input,
presence-only token checks, trusting spoofable headers (X-Forwarded-For,
X-Original-URL, X-Gitlab-Workhorse-Api-Request), hardcoded credential
comparisons. Safe markers (login_required, current_user, session) skip.
"""

import re

from blastradius.scanners._util import (
    code_has_source,
    has_source,
    make_finding,
    references_variable,
    scan_lines,
)

_SINKS = [
    r"\b(?:role|is_admin|isadmin|admin|user_type|privilege|is_superuser|group)\s*=\s*"
    r"(?:request\.|req\.|context\.|body\[|params\[|data\[|json\[)",
    r"\bif\s+(?:request\.|req\.|context\.|body|params|data)\.?(?:args|form|values|get_json)?"
    r"\s*\.?get?\(?[^)]*['\"](?:admin|role|is_admin|is_superuser|user_type)['\"]",
    r"\bif\s+(?:token|auth|api_key|key|session_id|passwd)\s*:",
    r"headers?\s*\[[\"'](?:X-Forwarded-For|X-Real-IP|X-Original-URL|X-Rewrite-URL|"
    r"X-Forwarded-Host|X-Forwarded-Proto)[\"']\]",
    r"(?:get_remote_addr|client_ip|remote_addr|REMOTE_ADDR)\s*=.*(?:X-Forwarded|X-Real-IP)",
    r"X-Gitlab-Workhorse-Api-Request|Workhorse\.verify_api_request",
]
_CRED_COMPARE = re.compile(
    r"(?:password|passwd|pass|pwd)\s*==\s*['\"](?:admin|password|1234|123456|root|test)['\"]",
    re.I,
)
_SAFE = re.compile(
    r"login_required|is_authenticated|current_user|@login|@auth|@admin_required|"
    r"requires_auth|jwt\.require|verify_token|check_permission|has_access|"
    r"permission_required|roles_required|session\[|secure_session|access_control",
    re.I,
)


class AuthBypassScanner:
    """Pattern-based authentication bypass scanner."""

    name = "auth_bypass"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if _SAFE.search(line):
                return None
            if _CRED_COMPARE.search(line):
                return make_finding(
                    path,
                    idx,
                    "auth_bypass",
                    line.strip(),
                    0.8,
                    "HIGH",
                    "CWE-287",
                    "Authentication bypass: hardcoded/default credential comparison.",
                    "Load credentials from a secret manager and verify against hashes; never hardcode.",
                )
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if not references_variable(line):
                return None
            confidence = 0.85 if (has_source(line) or has_source_flag) else 0.75
            return make_finding(
                path,
                idx,
                "auth_bypass",
                line.strip(),
                confidence,
                "HIGH",
                "CWE-287",
                "Authentication bypass: authorization decided by client-controlled values.",
                "Derive identity/privileges from a server-side session; never trust client-supplied roles or headers.",
            )

        return scan_lines(code, path, check)
