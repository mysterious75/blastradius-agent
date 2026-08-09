"""Sandbox escape prevention (stdlib only).

- verify_docker_flags: every docker run must include the isolation flags
- running_as_root: warn when scanning as root
- enforce_file_size: cap files written into the sandbox (1MB)
- verify_command: only python may run inside the sandbox
- detect_sandbox_escape: spot escape attempts in captured output
"""

import os
import re
from typing import List

MAX_SANDBOX_FILE_BYTES = 1_000_000  # 1MB

REQUIRED_DOCKER_FLAGS = {
    "--network": "none",
    "--read-only": None,   # presence-only flag
}

ALLOWED_COMMANDS = ("python",)

_ESCAPE_PATTERNS = [
    r"/etc/shadow",
    r"uid=0\(",
    r"nsenter",
    r"--privileged",
    r"docker\.sock",
    r"/proc/1/root",
    r"breakout",
    r"mknod",
    r"CAP_SYS_ADMIN",
    r"chroot",
]


def verify_docker_flags(cmd: List[str]) -> bool:
    """True when the docker command carries the required isolation flags."""
    if not cmd or cmd[0] != "docker":
        return False
    for flag, value in REQUIRED_DOCKER_FLAGS.items():
        if flag not in cmd:
            return False
        if value is not None:
            idx = cmd.index(flag)
            if idx + 1 >= len(cmd) or cmd[idx + 1] != value:
                return False
    return True


def running_as_root() -> bool:
    """True when the process runs as root (POSIX)."""
    if os.name != "posix":
        return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def enforce_file_size(code: str) -> None:
    """Raise ValueError when code exceeds the sandbox file size cap."""
    size = len(code.encode("utf-8"))
    if size > MAX_SANDBOX_FILE_BYTES:
        raise ValueError(
            f"sandbox file exceeds {MAX_SANDBOX_FILE_BYTES // 1024}KB limit ({size} bytes)"
        )


def verify_command(cmd: List[str]) -> bool:
    """True when the command runs the allowed interpreter (python only)."""
    if not cmd:
        return False
    base = os.path.basename(cmd[0]).lower()
    return any(base == allowed or base.startswith(allowed) for allowed in ALLOWED_COMMANDS)


def detect_sandbox_escape(output: str) -> List[str]:
    """Patterns in the sandbox output that suggest an escape attempt."""
    if not output:
        return []
    return [pattern for pattern in _ESCAPE_PATTERNS if re.search(pattern, output, re.I)]
