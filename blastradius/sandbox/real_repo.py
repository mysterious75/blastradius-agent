"""REAL-repo PoC execution — prove a finding against the actual repo file.

The synthetic path (``reconstruct_target_code``) proves the *pattern* a
finding matched is exploitable. This module instead drives the function that
literally exists in the scanned repo, so a confirmed result means the real
code — not a replica — is exploitable (the "hermes lesson"). Fail-closed: a
finding whose real file has no PoC-able function is reported as not
vulnerable with an explicit error, never as confirmed.
"""

from blastradius.hunter.scanner import real_target_code
from blastradius.sandbox.generator import generate_exploit
from blastradius.sandbox.runner import SandboxRunner


def run_real_poc(finding, repo_path: str, timeout: int = 10) -> dict:
    """Run the exploit for ``finding.vuln_type`` against the REAL repo function.

    Builds the target snippet from the actual file via ``real_target_code``
    and runs the template exploit for the vuln type (same payloads as the
    synthetic path) through the sandbox. The PoC is template-generated
    (trusted), so the runner may fall back to the unsandboxed local
    subprocess — mirroring ``run_exploit_sandbox``.

    Args:
        finding: A ``blastradius.hunter.scanner.Finding``.
        repo_path: Local repo root the finding was scanned from.
        timeout: Sandbox timeout in seconds (default 10).

    Returns:
        ``{"vulnerable": bool, "output": str, "real_file": True, ...}`` from
        the sandbox run, or ``{"vulnerable": False, "error": ...}`` when no
        PoC-able function exists in the real file.
    """
    snippet = real_target_code(finding, repo_path)
    if not snippet:
        return {"vulnerable": False, "error": "no real target function"}
    try:
        exploit = generate_exploit(finding.vuln_type, snippet)
    except ValueError as exc:
        return {"vulnerable": False, "error": f"no exploit template: {exc}"}
    result = SandboxRunner(allow_unsandboxed=True, timeout=timeout).run(exploit, snippet)
    result["real_file"] = True
    return result
