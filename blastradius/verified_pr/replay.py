"""Exploit replay — prove a fix against the REAL code, not a reconstruction.

The sandbox PoC templates only need a namespace with a callable named
``target``. Instead of feeding them a synthetic reconstruction, replay builds
a harness from the actual file: the real enclosing function of the flagged
line, aliased to ``target``, executed with the REAL exploit payloads:

- pre-patch replay: the original payloads must yield ``[VULNERABLE]`` —
  genuine exploitability of the real code (stronger than pattern matching);
- post-patch replay: the canonical payloads must be neutralized AND a fixed
  bypass battery (XBOW-style mutated variants, not just the original PoC)
  must be blocked AND benign input must still work (regression).

Outcome discipline (never confuse "harness broken" with "fix proven"):

- ``BLOCKED`` — exploit path demonstrably closed (evidence attached);
- ``STILL_VULNERABLE`` — a payload (canonical or bypass) still succeeds;
- ``INCONCLUSIVE`` — the harness could not run (unsupported shape, unsafe
  top-level code, load/call failure, benign breakage). The caller must fall
  back to weaker evidence or fail closed — never to FIXED.

Scope (deterministic, documented): Python files whose flagged line sits in a
module-level function, with a side-effect-free top level (imports, defs,
constant assignments only). Everything else is INCONCLUSIVE by construction.
Real code executes only inside SandboxRunner (Docker preferred, explicit
opt-in local fallback — the same trust basis as template PoCs, and no
stronger than the CI checkout trust the code already enjoys).
"""

import ast
from dataclasses import dataclass
from typing import List, Optional, Tuple

from blastradius.sandbox.generator import VALID_VULN_TYPES, generate_exploit
from blastradius.sandbox.runner import VULNERABLE_MARKER, SandboxRunner

# Fixed bypass batteries per vuln type (XBOW-style mutated variants: a fix
# that only blocks the exact original payload must still be caught).
BYPASS_PAYLOADS = {
    "sqli": [
        '" OR "1"="1',  # double-quote variant (no single quotes to double)
        "' OR 1=1--",  # comment without trailing space
        "';SELECT 1;--",  # stacked statement
        "\\' OR 1=1 --",  # backslash-escaped quote
    ],
    "xss": [
        "<svg onload=alert(1)>",  # non-script tag, event handler
        "<ScRiPt>alert(1)</ScRiPt>",  # case variant
        "<iframe src=javascript:alert(1)>",  # URL-context payload
        "<body onload=alert(1)>",  # body handler
    ],
}

BENIGN_INPUT = "alice"

# Top-level statements allowed in a replay harness (side-effect-free set).
_SAFE_TOP_LEVEL = (
    ast.Import,
    ast.ImportFrom,
    ast.FunctionDef,
    ast.ClassDef,
    ast.Assign,
    ast.AnnAssign,
    ast.Pass,
)

REPLAY_BLOCKED = "BLOCKED"
REPLAY_STILL_VULNERABLE = "STILL_VULNERABLE"
REPLAY_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ReplayResult:
    """Outcome of replaying exploits against real (harnessed) code."""

    status: str = REPLAY_INCONCLUSIVE
    evidence: str = ""
    bypass_blocked: int = 0
    bypass_total: int = 0
    benign_ok: bool = False
    real_exploit_shown: bool = False


def extract_harness(file_content: str, line_no: int) -> Tuple[Optional[str], str]:
    """Build a ``target``-aliased harness from the real file.

    Returns ``(harness_source, "")`` on success, or ``(None, reason)`` when
    the file shape is outside the deterministic replay scope.
    """
    try:
        tree = ast.parse(file_content)
    except SyntaxError as exc:
        return None, f"file does not parse: {exc}"
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # module docstring
        if not isinstance(node, _SAFE_TOP_LEVEL):
            return (
                None,
                f"top-level {type(node).__name__} is outside the replay scope "
                "(imports, defs and constant assignments only)",
            )
    func: Optional[ast.FunctionDef] = None
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        if start <= line_no <= end:
            if func is None or start > func.lineno:
                func = node  # innermost enclosing function
    if func is None:
        return None, f"line {line_no} is not inside a module-level function"
    if not func.args.args and not func.args.vararg:
        return None, f"function {func.name!r} takes no arguments to attack"
    harness = file_content
    if not harness.endswith("\n"):
        harness += "\n"
    harness += f"\ntarget = {func.name}\n"
    return harness, ""


def _run_harness(harness: str, probe: str, runner: SandboxRunner) -> dict:
    """Execute ``probe`` (which execs the harness) via the sandbox runner."""
    return runner.run(probe, harness)


def _canonical_replay(vuln_type: str, harness: str, runner: SandboxRunner) -> Tuple[str, str]:
    """Run the canonical template PoC. Returns (marker, output excerpt)."""
    try:
        exploit = generate_exploit(vuln_type, harness)
    except ValueError as exc:
        return REPLAY_INCONCLUSIVE, f"no exploit template for {vuln_type}: {exc}"
    try:
        result = _run_harness(harness, exploit, runner)
    except Exception as exc:
        return REPLAY_INCONCLUSIVE, f"sandbox run crashed: {exc}"
    output = (result.get("output") or "") + (result.get("error") or "")
    if VULNERABLE_MARKER in (result.get("output") or ""):
        return REPLAY_STILL_VULNERABLE, _excerpt(output, 6)
    if "failed to load" in output or "target failed" in output:
        return REPLAY_INCONCLUSIVE, f"harness did not load: {_excerpt(output, 3)}"
    return REPLAY_BLOCKED, _excerpt(output, 4)


def _excerpt(output: str, max_lines: int) -> str:
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    return "\n".join(lines[:max_lines])[:2000]


_BENIGN_PROBE = """\
HARNESS = __HARNESS__

def main():
    ns = {}
    try:
        exec(compile(HARNESS, "<harness>", "exec"), ns)
        target = ns["target"]
    except Exception as exc:
        print(f"BENIGN_FAIL: harness failed to load: {exc}")
        return
    try:
        result = target(__BENIGN__)
    except Exception as exc:
        print(f"BENIGN_FAIL: benign input raised: {exc}")
        return
    if not isinstance(result, str) or not result:
        print(f"BENIGN_FAIL: benign input gave non-string/empty: {result!r}")
        return
    if __BENIGN__ not in result:
        print(f"BENIGN_WARN: benign input altered: {result!r}")
        return
    print("BENIGN_OK")
    print(result)


if __name__ == "__main__":
    main()
"""

_BYPASS_PROBE = """\
HARNESS = __HARNESS__
PAYLOADS = __PAYLOADS__
HIT_ON_EXCEPTION = __HIT_ON_EXCEPTION__

def main():
    ns = {}
    try:
        exec(compile(HARNESS, "<harness>", "exec"), ns)
        target = ns["target"]
    except Exception as exc:
        print(f"BYPASS_INCONCLUSIVE: harness failed to load: {exc}")
        return
    for payload in PAYLOADS:
        try:
            result = target(payload)
        except Exception as exc:
            if HIT_ON_EXCEPTION:
                print(f"BYPASS_HIT: payload caused exception: {payload!r} ({exc})")
                return
            continue
        if payload in str(result):
            print(f"BYPASS_HIT: payload reflected unescaped: {payload!r}")
            return
    print("BYPASS_BLOCKED_ALL")


if __name__ == "__main__":
    main()
"""


def _hit_on_exception(vuln_type: str) -> bool:
    """Mirror each template's own oracle: sqli treats errors as signal."""
    return vuln_type == "sqli"


def run_bypass_probe(
    vuln_type: str, harness: str, runner: Optional[SandboxRunner] = None
) -> Tuple[str, str]:
    """Run only the mutated bypass battery against harnessed real code.

    Returns ``("HIT" | "BLOCKED" | "INCONCLUSIVE", evidence)``. ``HIT`` means
    a mutated variant demonstrably reaches the sink — genuine exploitability
    even when the canonical payload is neutralized (weak-fix detector).
    """
    runner = runner or SandboxRunner(allow_unsandboxed=True)
    battery = BYPASS_PAYLOADS[vuln_type]
    probe = (
        _BYPASS_PROBE.replace("__HARNESS__", repr(harness))
        .replace("__PAYLOADS__", repr(battery))
        .replace("__HIT_ON_EXCEPTION__", repr(_hit_on_exception(vuln_type)))
    )
    try:
        bypass = _run_harness(harness, probe, runner)
    except Exception as exc:
        return "INCONCLUSIVE", f"bypass run crashed: {exc}"
    bypass_out = bypass.get("output") or ""
    if "BYPASS_INCONCLUSIVE" in bypass_out:
        return "INCONCLUSIVE", f"bypass harness failed: {_excerpt(bypass_out, 3)}"
    if "BYPASS_HIT" in bypass_out:
        return "HIT", f"bypass payload reached the sink:\n{_excerpt(bypass_out, 4)}"
    return "BLOCKED", f"{len(battery)}/{len(battery)} bypass payloads blocked"


def verify_fix(
    vuln_type: str,
    harness: str,
    runner: Optional[SandboxRunner] = None,
) -> ReplayResult:
    """Full replay verdict for already-patched real code.

    Canonical PoC first, then the bypass battery, then the benign check. Any
    harness failure is INCONCLUSIVE — never evidence of a fix.
    """
    if vuln_type not in VALID_VULN_TYPES or vuln_type not in BYPASS_PAYLOADS:
        return ReplayResult(
            status=REPLAY_INCONCLUSIVE,
            evidence=f"vuln_type {vuln_type!r} has no replay battery",
        )
    runner = runner or SandboxRunner(allow_unsandboxed=True)

    marker, excerpt = _canonical_replay(vuln_type, harness, runner)
    if marker == REPLAY_STILL_VULNERABLE:
        return ReplayResult(
            status=REPLAY_STILL_VULNERABLE,
            evidence=f"canonical PoC still succeeds on patched code:\n{excerpt}",
        )
    if marker == REPLAY_INCONCLUSIVE:
        return ReplayResult(status=REPLAY_INCONCLUSIVE, evidence=excerpt)

    battery = BYPASS_PAYLOADS[vuln_type]
    verdict, bypass_evidence = run_bypass_probe(vuln_type, harness, runner)
    if verdict == "INCONCLUSIVE":
        return ReplayResult(
            status=REPLAY_INCONCLUSIVE,
            evidence=f"bypass harness failed: {bypass_evidence}",
        )
    if verdict == "HIT":
        return ReplayResult(
            status=REPLAY_STILL_VULNERABLE,
            bypass_blocked=0,
            bypass_total=len(battery),
            evidence=f"bypass payload defeated the patch:\n{bypass_evidence}",
        )

    benign_probe = _BENIGN_PROBE.replace("__HARNESS__", repr(harness)).replace(
        "__BENIGN__", repr(BENIGN_INPUT)
    )
    try:
        benign = _run_harness(harness, benign_probe, runner)
    except Exception as exc:
        return ReplayResult(status=REPLAY_INCONCLUSIVE, evidence=f"benign run crashed: {exc}")
    benign_out = benign.get("output") or ""
    if "BENIGN_OK" not in benign_out:
        return ReplayResult(
            status=REPLAY_INCONCLUSIVE,
            bypass_blocked=len(battery),
            bypass_total=len(battery),
            evidence=f"benign behavior broken, fix not trustworthy: {_excerpt(benign_out, 4)}",
        )
    return ReplayResult(
        status=REPLAY_BLOCKED,
        evidence=(
            f"canonical PoC neutralized ({excerpt}); "
            f"{len(battery)}/{len(battery)} bypass payloads blocked; "
            f"benign input {BENIGN_INPUT!r} preserved"
        ),
        bypass_blocked=len(battery),
        bypass_total=len(battery),
        benign_ok=True,
    )


def prove_real_exploit(
    vuln_type: str,
    harness: str,
    runner: Optional[SandboxRunner] = None,
) -> ReplayResult:
    """Replay the canonical PoC against PRE-patch real code.

    BLOCKED here is impossible by construction (nothing patched yet); a
    ``[VULNERABLE]`` run proves the real code — not a reconstruction — is
    genuinely exploitable. Anything else is INCONCLUSIVE (the synthetic
    confirm path stays authoritative).
    """
    if vuln_type not in VALID_VULN_TYPES:
        return ReplayResult(
            status=REPLAY_INCONCLUSIVE,
            evidence=f"vuln_type {vuln_type!r} has no exploit template",
        )
    runner = runner or SandboxRunner(allow_unsandboxed=True)
    marker, excerpt = _canonical_replay(vuln_type, harness, runner)
    if marker == REPLAY_STILL_VULNERABLE:
        return ReplayResult(
            status=REPLAY_STILL_VULNERABLE,
            real_exploit_shown=True,
            evidence=f"real code is genuinely exploitable:\n{excerpt}",
        )
    return ReplayResult(
        status=REPLAY_INCONCLUSIVE,
        evidence=f"real-code replay did not confirm: {excerpt}",
    )


def supported_types() -> List[str]:
    """Vuln types with a replay battery."""
    return sorted(BYPASS_PAYLOADS)
