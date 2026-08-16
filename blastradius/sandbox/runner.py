"""SandboxRunner — executes exploit PoCs in an isolated sandbox.

Production path (Docker):
    docker run --rm --network none --read-only --memory=128m
           --runtime=runsc -v <tmp>:/app blastradius-sandbox

    ``--network none`` (no egress), ``--read-only`` (read-only FS),
    ``--memory`` (memory limit), ``--runtime=runsc`` (gVisor syscall
    interception). If gVisor is not installed on the host, the runner
    retries once on Docker's default runtime.

Local path (use_docker=False, CI/dev without a daemon):
    runs ``python exploit_poc.py`` in a subprocess with the same timeout.
    This mode is weaker (no network/FS isolation) and must only be used
    with trusted PoC code. It is opt-in only: either the caller explicitly
    passes ``use_docker=False`` or ``BLASTRADIUS_ALLOW_UNSANDBOXED=1`` is
    set. Without Docker and without that opt-in, the run fails closed
    instead of executing PoCs without isolation.

Detection: a run is considered vulnerable when the exploit's stdout
contains the marker ``[VULNERABLE]``.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator, List, Optional

from blastradius.security.input_validator import validate_target_code

VULNERABLE_MARKER = "[VULNERABLE]"

_docker_checked: bool = False
_docker_ok: bool = False


def _docker_available() -> bool:
    """Whether a reachable docker daemon exists (checked once per process)."""
    global _docker_checked, _docker_ok
    if not _docker_checked:
        _docker_checked = True
        if shutil.which("docker") is None:
            _docker_ok = False
        else:
            probe = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
            _docker_ok = probe.returncode == 0
    return _docker_ok


class SandboxRunner:
    """Isolate and execute an exploit PoC against target code."""

    def __init__(
        self,
        timeout: int = 10,
        memory_mb: int = 128,
        runtime: Optional[str] = "runsc",
        image: str = "blastradius-sandbox",
        use_docker: Optional[bool] = None,
        allow_unsandboxed: Optional[bool] = None,
    ):
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.runtime = runtime
        self.image = image
        # None -> auto-detect a reachable docker daemon; False -> local subprocess.
        self.use_docker = use_docker
        # Explicit opt-in for the unsandboxed fallback (trusted callers only,
        # e.g. template-generated PoCs). Falls back to the env var otherwise.
        self.allow_unsandboxed = allow_unsandboxed

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, exploit_code: str, target_code: str) -> dict:
        """Run ``exploit_code`` (PoC) against ``target_code`` in the sandbox.

        ``target_code`` is validated first (50KB cap, prompt-injection
        blocking). Hardening: docker flags verified, file sizes capped,
        escape attempts detected. Returns:
            {"vulnerable": bool, "output": str, "error": str, "exit_code": int}
        """
        from blastradius.security.sandbox_escape_prevention import (
            detect_sandbox_escape,
            enforce_file_size,
            running_as_root,
            verify_command,
            verify_docker_flags,
        )

        validate_target_code(target_code)
        enforce_file_size(exploit_code)
        enforce_file_size(target_code)
        self.warnings = []
        self.escape_flags = []
        if running_as_root():
            self.warnings.append("running as root — sandbox isolation is weaker")
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "exploit_poc.py").write_text(exploit_code, encoding="utf-8")
            (Path(tmpdir) / "target_code.py").write_text(target_code, encoding="utf-8")

            result = None
            for cmd in self._candidate_commands(tmpdir):
                if not verify_command(cmd):
                    self.warnings.append(f"command not on allowlist: {cmd[0] if cmd else '?'}")
                if not self._use_docker() and self.runtime and not verify_docker_flags(cmd):
                    self.warnings.append("docker isolation flags missing")
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=self.timeout
                    )
                except subprocess.TimeoutExpired:
                    return {
                        "vulnerable": False,
                        "output": "",
                        "error": f"sandbox timed out after {self.timeout}s",
                        "exit_code": -1,
                    }
                if cmd[0] != "docker":
                    self.warnings.append(
                        "running exploit as a local subprocess (unsandboxed — opt-in only)"
                    )
                if result.returncode == 0:
                    break  # execution succeeded — keep this result
                # docker failed (e.g. runtime or image missing) — try the next
                # fallback candidate, ending with the local subprocess (opt-in)
                if cmd[0] == "docker":
                    self.warnings.append("docker run failed; trying next candidate")

        if result is None:
            return {
                "vulnerable": False,
                "output": "",
                "error": (
                    "no sandbox available: docker is unreachable and unsandboxed "
                    "execution is disabled; set BLASTRADIUS_ALLOW_UNSANDBOXED=1 "
                    "to force local execution (unsafe)"
                ),
                "exit_code": -1,
            }

        self.escape_flags = detect_sandbox_escape(result.stdout)
        return {
            "vulnerable": VULNERABLE_MARKER in result.stdout,
            "output": result.stdout,
            "error": result.stderr,
            "exit_code": result.returncode,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _candidate_commands(self, tmpdir: str) -> Iterator[List[str]]:
        """Yield commands to try, most preferred first.

        Docker (runsc, then the default runtime) is always attempted when a
        daemon is reachable. The local subprocess is a last-resort fallback
        that is ONLY offered on explicit opt-in (``use_docker=False`` or
        ``BLASTRADIUS_ALLOW_UNSANDBOXED=1``) — otherwise the run fails closed
        rather than executing PoCs without isolation.
        """
        if self._use_docker():
            yield self._docker_command(tmpdir, with_runtime=True)
            if self.runtime:
                yield self._docker_command(tmpdir, with_runtime=False)
        if self._allow_unsandboxed():
            yield [sys.executable, str(Path(tmpdir) / "exploit_poc.py")]

    def _allow_unsandboxed(self) -> bool:
        """Whether unsandboxed local execution is permitted (explicit opt-in)."""
        if self.allow_unsandboxed is True:
            return True
        if self.use_docker is False:
            return True
        return os.getenv("BLASTRADIUS_ALLOW_UNSANDBOXED", "").lower() in (
            "1",
            "true",
            "yes",
        )

    def _use_docker(self) -> bool:
        if self.use_docker is None:
            return _docker_available()
        return self.use_docker

    def _docker_command(self, tmpdir: str, with_runtime: bool) -> List[str]:
        cmd = ["docker", "run", "--rm"]
        if with_runtime and self.runtime:
            cmd += ["--runtime", self.runtime]
        cmd += [
            "--network",
            "none",
            "--read-only",
            f"--memory={self.memory_mb}m",
            "-v",
            f"{tmpdir}:/app",
            self.image,
        ]
        return cmd
