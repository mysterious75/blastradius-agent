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
    with trusted PoC code.

Detection: a run is considered vulnerable when the exploit's stdout
contains the marker ``[VULNERABLE]``.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator, List, Optional

from blastradius.security.input_validator import validate_target_code

VULNERABLE_MARKER = "[VULNERABLE]"

_RUNTIME_MISSING_MARKERS = ("unknown runtime", "not found", "does not exist")

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
            probe = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=5
            )
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
    ):
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.runtime = runtime
        self.image = image
        # None -> auto-detect a reachable docker daemon; False -> local subprocess.
        self.use_docker = use_docker

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, exploit_code: str, target_code: str) -> dict:
        """Run ``exploit_code`` (PoC) against ``target_code`` in the sandbox.

        ``target_code`` is validated first (50KB cap, prompt-injection
        blocking). Returns:
            {"vulnerable": bool, "output": str, "error": str, "exit_code": int}
        """
        validate_target_code(target_code)
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "exploit_poc.py").write_text(exploit_code, encoding="utf-8")
            (Path(tmpdir) / "target_code.py").write_text(target_code, encoding="utf-8")

            result = None
            for cmd in self._candidate_commands(tmpdir):
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
                if not self._is_missing_runtime(result):
                    break

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
        """Yield commands to try, most preferred first (docker, then fallback)."""
        if self._use_docker():
            yield self._docker_command(tmpdir, with_runtime=True)
            if self.runtime:
                yield self._docker_command(tmpdir, with_runtime=False)
        else:
            yield [sys.executable, str(Path(tmpdir) / "exploit_poc.py")]

    def _use_docker(self) -> bool:
        if self.use_docker is None:
            return _docker_available()
        return self.use_docker

    def _is_missing_runtime(self, result: subprocess.CompletedProcess) -> bool:
        if result.returncode == 0 or not self.runtime:
            return False
        stderr = result.stderr.lower()
        return any(marker in stderr for marker in _RUNTIME_MISSING_MARKERS)

    def _docker_command(self, tmpdir: str, with_runtime: bool) -> List[str]:
        cmd = ["docker", "run", "--rm"]
        if with_runtime and self.runtime:
            cmd += ["--runtime", self.runtime]
        cmd += [
            "--network", "none",
            "--read-only",
            f"--memory={self.memory_mb}m",
            "-v", f"{tmpdir}:/app",
            self.image,
        ]
        return cmd
