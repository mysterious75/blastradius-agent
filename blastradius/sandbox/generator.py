"""Exploit generator — renders exploit templates for a vuln type + target code.

Each template is a standalone Python PoC that embeds the target code and
prints ``[VULNERABLE]`` when the attack succeeds.
"""

from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent / "exploit_templates"

VALID_VULN_TYPES = {
    "sqli",
    "xss",
    "ssrf",
    "ssti",
    "jwt",
    "deserialization",
    "cmd_injection",
    "traversal",
    "crlf",
    "auth_bypass",
}

_TEMPLATE_FILES = {
    "sqli": "sqli_exploit.py.template",
    "xss": "xss_exploit.py.template",
    "ssrf": "ssrf_exploit.py.template",
    "ssti": "ssti_exploit.py.template",
    "jwt": "jwt_exploit.py.template",
    "deserialization": "deserialization_exploit.py.template",
    "cmd_injection": "cmd_injection_exploit.py.template",
    "traversal": "traversal_exploit.py.template",
    "crlf": "crlf_exploit.py.template",
    "auth_bypass": "auth_bypass_exploit.py.template",
}


def generate_exploit(vuln_type: str, target_code: str) -> str:
    """Render the exploit PoC for ``vuln_type`` against ``target_code``.

    Raises ValueError for unsupported vuln types.
    """
    if vuln_type not in VALID_VULN_TYPES:
        raise ValueError(
            f"Unsupported vuln_type {vuln_type!r}; expected one of {sorted(VALID_VULN_TYPES)}"
        )
    template = (TEMPLATE_DIR / _TEMPLATE_FILES[vuln_type]).read_text(encoding="utf-8")
    return template.replace("__TARGET_CODE__", repr(target_code))
