"""CmdInjectionScanner — self-contained OS command / code injection detection.

Sinks: os.system/popen, subprocess with shell=True, exec/eval, shell_exec,
passthru, Runtime.exec, child_process.exec, execSync. Safe markers (list-form
subprocess, shlex.quote, escapeshellarg) are skipped; regex `.exec(` is not
flagged (excluded after a dot).
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
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"subprocess\.(?:run|call|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True",
    r"(?<![.\w])exec\s*\(",
    r"\beval\s*\(",
    r"\bexecfile\s*\(",
    r"\bexecSync\s*\(",
    r"child_process\.(?:exec|execSync|spawn)\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpassthru\s*\(",
    r"\bsystem\s*\(",
    r"\bpopen\s*\(",
    r"Runtime\.getRuntime\(\).*\.exec\s*\(",
    r"\bProcessBuilder\s*\(",
]
_SAFE = re.compile(
    r"shlex\.quote|shell\s*=\s*False|escapeShellArg|escapeshellarg|escapeshellcmd|"
    r"shellescape|validate_command|allowlist|"
    r"subprocess\.(?:run|call|Popen)\s*\(\s*\[",
    re.I,
)

# exec/eval-family sinks (sandboxed-exec downgrade applies only to these).
_EXEC_SINKS = [
    r"(?<![.\w])exec\s*\(",
    r"\beval\s*\(",
    r"\bexecfile\s*\(",
    r"\bexecSync\s*\(",
]

# Markers indicating a SANDBOXED interpreter (restricted globals/builtins,
# sanitized-AST validation, allowlisted imports) rather than attacker code exec.
_SANDBOXED_EXEC = re.compile(
    r"safe_globals|restricted_builtins|safe_builtins|"
    r"ast\.|\bAST\b|validate_node|validate_ast|_ast_validate|"
    r"sandbox|allowlist|blocklist.*import",
    re.I,
)


class CmdInjectionScanner:
    """Pattern-based OS command injection scanner."""

    name = "cmd_injection"

    def detect(self, code: str, path=None):
        has_source_flag = code_has_source(code)

        def check(line, idx):
            if not any(re.search(p, line, re.I) for p in _SINKS):
                return None
            if any(re.search(p, line, re.I) for p in _EXEC_SINKS) and _SANDBOXED_EXEC.search(line):
                # sandboxed exec/eval (restricted builtins / sanitized AST /
                # allowlisted imports): below the 0.7 candidate threshold —
                # still discoverable via code_flows / real-repo targets.
                return make_finding(
                    path,
                    idx,
                    "cmd_injection",
                    line.strip(),
                    0.55,
                    "CRITICAL",
                    "CWE-78",
                    "Command/code injection: user input reaches an OS command or eval sink.",
                    "Use list-form subprocess without shell=True and an allowlist; never eval user input.",
                )
            if _SAFE.search(line):
                return None
            if not references_variable(line):
                return None
            confidence = 0.9 if (has_source(line) or has_source_flag) else 0.75
            return make_finding(
                path,
                idx,
                "cmd_injection",
                line.strip(),
                confidence,
                "CRITICAL",
                "CWE-78",
                "Command/code injection: user input reaches an OS command or eval sink.",
                "Use list-form subprocess without shell=True and an allowlist; never eval user input.",
            )

        return scan_lines(code, path, check)
