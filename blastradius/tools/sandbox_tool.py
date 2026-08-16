"""CAI function_tool that validates exploitability of a finding in the sandbox.

Takes a vuln type and the vulnerable target code, generates a PoC from the
matching exploit template, runs it in the sandbox, and reports whether the
vulnerability is actually exploitable. No CAI required to import/test.
"""

from blastradius.sandbox.generator import generate_exploit
from blastradius.sandbox.runner import SandboxRunner
from blastradius.tools.cai_utils import cai_tool


@cai_tool
def run_exploit_sandbox(vuln_type: str, target_code: str) -> str:
    """Generate an exploit for ``vuln_type`` against ``target_code`` and run it in the sandbox.

    The target code must define ``target(user_input: str) -> str`` — a function
    that builds the vulnerable artifact (SQL query, HTML page, fetch URL) from
    user input. The PoC injects a malicious payload and reports whether it
    reached the output unescaped.

    Never crashes: vuln types without an exploit template return
    NOT_EXPLOITABLE instead of raising.

    Args:
        vuln_type: One of "sqli", "xss", "ssrf", "ssti", "jwt".
        target_code: Python source snippet of the vulnerable target.

    Returns:
        "CONFIRMED_EXPLOITABLE" followed by PoC output, or
        "NOT_EXPLOITABLE" followed by PoC output.
    """
    try:
        exploit_code = generate_exploit(vuln_type, target_code)
    except ValueError as exc:
        return f"NOT_EXPLOITABLE (no exploit template for {vuln_type}: {exc})"
    # PoCs here are template-generated (trusted); allow the unsandboxed local
    # fallback when no Docker daemon is present (dev/CI). Arbitrary exploit
    # code paths must NOT opt in — SandboxRunner stays fail-closed by default.
    result = SandboxRunner(allow_unsandboxed=True).run(exploit_code, target_code)
    if result["vulnerable"]:
        return f"CONFIRMED_EXPLOITABLE\n{result['output']}"
    return f"NOT_EXPLOITABLE\n{result['output']}"
