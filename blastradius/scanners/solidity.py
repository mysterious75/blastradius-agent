"""SolidityScanner - self-contained smart-contract defect detection.

Rule set aligned with the Slither detector catalogue (the industry reference
for Solidity static analysis), restricted to the classes that are decidable
from source text without a full AST:

- reentrancy             external value call, then a later state write (CWE-841)
- unchecked-lowlevel     ``call``/``send`` return value discarded (CWE-252)
- unchecked-transfer     ERC20 ``transfer``/``transferFrom`` not checked (CWE-252)
- tx-origin              authorisation on ``tx.origin`` (CWE-807)
- weak-prng              randomness from block state via modulo (CWE-330)
- controlled-delegatecall  delegatecall to a non-constant target (CWE-829)
- arbitrary-send         value sent to a function-parameter address (CWE-284)
- unprotected-upgrade    ``selfdestruct`` in an upgradeable contract (CWE-506)
- integer-overflow       pre-0.8 arithmetic without SafeMath (CWE-190)
- divide-before-multiply truncation before scaling (CWE-682)
- incorrect-exp          non-constant right operand on ``**`` (CWE-682)
- timestamp-dependency   deadline logic on manipulable block time (CWE-349)
- hardcoded-private-key  32-byte key literal in source (CWE-798)

Every finding is a *candidate* for sandbox/analyst confirmation, exactly like
the other scanners in this package: pattern presence is not proof of
exploitability, and ``checks-effects-interactions`` code that merely looks
like reentrancy is downgraded rather than dropped.
"""

import re
from typing import List, Optional, Tuple

from blastradius.scanners._util import make_finding, scan_lines

VULN_TYPE = "solidity"

# Lines that are comments or documentation, not executable code.
_COMMENT_RE = re.compile(r"^\s*(?://|/\*|\*|pragma\s+solidity)")

# ------------------------------------------------------------------ rules

# External calls that hand control to another contract.
_EXTERNAL_CALL_RE = re.compile(
    r"\.\s*(?:call|delegatecall|staticcall)\s*[\({]"
    r"|\.\s*send\s*\("
    r"|\.\s*transfer\s*\("
    r"|\.\s*callcode\s*\("
)

# ``addr.call{value: x}("")`` sends value; ``addr.call("")`` does not.
_VALUE_CALL_RE = re.compile(r"\.call\s*\{\s*value\s*:")
_SEND_TRANSFER_RE = re.compile(r"\.\s*(?:send|transfer)\s*\(")

# Assignments to a state variable. Comparison operators are blanked out first
# so that ``require(a == b)`` is never mistaken for a state update.
_COMPARISON_RE = re.compile(r"(==|!=|<=|>=)")
_STATE_WRITE_RE = re.compile(r"[A-Za-z_]\w*\s*(?:\[[^\]]*\])*\s*(?:[-+*/%&|^]|<<|>>)?=(?![=])")
_LOCAL_DECL_RE = re.compile(r"\b(?:let|var|memory|calldata|storage)\b")

# A low-level call used as a bare statement (result discarded). The statement
# may start the line, the file, or follow a block/brace opener.
_BARE_CALL_RE = re.compile(
    r"(?:^|[{};])\s*[\w.()\[\]]+\s*\.\s*"
    r"(?:call|delegatecall|staticcall|send)\s*\("
)
_ASSIGNED_CALL_RE = re.compile(
    r"=\s*[\w.()\[\]]+\s*\.\s*(?:call|delegatecall|staticcall|send)\s*\("
)
_GUARDED_RE = re.compile(r"\b(?:require|assert)\s*\(|\bif\s*\(")

_ERC20_RETURN_RE = re.compile(
    r"[\w.()\[\]]+\s*\.\s*(?:transfer|transferFrom|safeTransfer|approve)\s*\("
)
_SAFE_ERC20_RE = re.compile(
    r"SafeERC20|using\s+SafeERC20|\bsafeTransfer\b|\bsafeTransferFrom\b|\bsafeApprove\b"
)

_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")

_WEAK_RNG_RE = re.compile(r"\b(?:block\.timestamp|block\.prevrandao|blockhash\s*\(|now)\b")
_MODULO_RE = re.compile(r"%")

_DELEGATECALL_RE = re.compile(r"\.\s*delegatecall\s*\(")
_CONSTANT_TARGET_RE = re.compile(r"0x[0-9a-fA-F]{40}|address\s*\(\s*0\s*\)")

_SEND_DEST_RE = re.compile(
    r"([A-Za-z_][\w]*)\s*\.\s*(?:transfer|send)\s*\("
    r"|payable\s*\(\s*([A-Za-z_][\w]*)\s*\)\s*\.\s*(?:transfer|send|call)\b"
)
_VALUE_CALL_DEST_RE = re.compile(r"([A-Za-z_][\w]*)\s*\.\s*call\s*\{\s*value\s*:")

_SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(")
_UPGRADEABLE_RE = re.compile(r"\binitializer\b|\bInitializable\b|\binitializerModifier\b|__gap")

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s*([^;]+);")
_SAFEMATH_RE = re.compile(r"\bSafeMath\b|\bunchecked\s*\{")
_ARITH_RE = re.compile(r"[\w)\]]\s*[+\-*]\s*[\w(]")

_DIV_THEN_MUL_RE = re.compile(r"/\s*[\w()]*\s*\*\s*[\w(]")

_POW_RE = re.compile(r"[\w)\]]\s*\*\*\s*([A-Za-z_][\w]*)")
_POW_LITERAL_RE = re.compile(r"[\w)\]]\s*\*\*\s*\d+")

_DEADLINE_RE = re.compile(
    r"\b(?:deadline|expiry|expires|expiration|maturity|endTime|end_time|"
    r"validUntil|vestingEnd|cliffEnd)\b",
    re.I,
)

_PRIVATE_KEY_RE = re.compile(r"\b(0x)?[0-9a-fA-F]{64}\b")
_KEY_CONTEXT_RE = re.compile(
    r"private[_-]?key|privKey|signingKey|secretKey|mnemonic|seed|wallet",
    re.I,
)
_PLACEHOLDER_RE = re.compile(
    r"0{16,}|f{16,}|deadbeef|cafebabe|1234567890abcdef|your[_-]?key|example|placeholder",
    re.I,
)

_FUNC_RE = re.compile(r"^\s*(?:function|constructor|receive|fallback)\b[^;{]*\{", re.M)
_MODIFIER_RE = re.compile(r"\bmodifier\s+(\w+)")


class SolidityScanner:
    """Pattern + light structural analysis for Solidity source files."""

    name = VULN_TYPE

    def detect(self, code: str, path=None) -> List:
        if not code or "pragma solidity" not in code and "contract " not in code:
            return []

        findings = []
        findings.extend(self._reentrancy(code, path))
        findings.extend(self._arbitrary_send(code, path))
        findings.extend(self._line_rules(code, path))
        findings.extend(self._overflow(code, path))
        return findings

    # ------------------------------------------------------------------
    # Structural: reentrancy
    # ------------------------------------------------------------------

    @staticmethod
    def _function_blocks(code: str) -> List[Tuple[int, str]]:
        """(first line number, body) for each top-level function/constructor."""
        lines = code.splitlines()
        blocks: List[Tuple[int, str]] = []
        starts = [i for i, ln in enumerate(lines) if _FUNC_RE.match(ln)]
        for start in starts:
            depth = 0
            body = []
            for i in range(start, len(lines)):
                line = lines[i]
                body.append(line)
                depth += line.count("{") - line.count("}")
                if depth <= 0 and "{" in line:
                    break
            blocks.append((start + 1, "\n".join(body)))
        return blocks

    def _reentrancy(self, code: str, path) -> List:
        findings = []
        for start_line, body in self._function_blocks(code):
            lines = body.splitlines()
            guarded = bool(re.search(r"\bnonReentrant\b|\breentrancyGuard\b", body, re.I))
            call_idx = None
            for offset, line in enumerate(lines):
                if _COMMENT_RE.match(line) or _LOCAL_DECL_RE.search(line):
                    continue
                if _EXTERNAL_CALL_RE.search(line) and (
                    _VALUE_CALL_RE.search(line) or _SEND_TRANSFER_RE.search(line)
                ):
                    call_idx = offset
                    break
            if call_idx is None:
                continue
            for offset in range(call_idx + 1, len(lines)):
                line = lines[offset]
                if _COMMENT_RE.match(line) or _LOCAL_DECL_RE.search(line):
                    continue
                if not _STATE_WRITE_RE.search(_COMPARISON_RE.sub("  ", line)):
                    continue
                confidence = 0.6 if guarded else 0.8
                findings.append(
                    make_finding(
                        path,
                        start_line + offset,
                        VULN_TYPE,
                        "reentrancy",
                        confidence,
                        "HIGH" if confidence >= 0.8 else "MEDIUM",
                        "CWE-841",
                        "Reentrancy: an external value call is followed by a state "
                        "update, so a callback can re-enter before the balance is "
                        "settled (checks-effects-interactions violation).",
                        "Apply checks-effects-interactions and a reentrancy guard; "
                        "update balances before the external call.",
                    )
                )
                break
        return findings

    def _arbitrary_send(self, code: str, path) -> List:
        """Value sent to an address that arrived as a function parameter."""
        findings = []
        for start_line, body in self._function_blocks(code):
            signature = body.split("{", 1)[0]
            params = set(re.findall(r"\b([A-Za-z_][\w]*)\b", signature.split(")")[0]))
            params.discard("function")
            params.discard("memory")
            params.discard("calldata")
            params.discard("storage")
            params.discard("payable")
            if not params:
                continue
            for offset, line in enumerate(body.splitlines()):
                if _COMMENT_RE.match(line) or _LOCAL_DECL_RE.search(line):
                    continue
                dest = _SEND_DEST_RE.search(line) or _VALUE_CALL_DEST_RE.search(line)
                if not dest:
                    continue
                recipient = next((g for g in dest.groups() if g), None)
                if recipient not in params:
                    continue
                findings.append(
                    make_finding(
                        path,
                        start_line + offset,
                        VULN_TYPE,
                        "arbitrary-send",
                        0.75,
                        "HIGH",
                        "CWE-284",
                        "Ether is sent to a caller-supplied address, so any user can "
                        "redirect protocol value to an account they control.",
                        "Send to a contract-determined recipient, or gate the payout path "
                        "behind an access-control check on the intended beneficiary.",
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Per-line rules
    # ------------------------------------------------------------------

    def _line_rules(self, code: str, path) -> List:
        def check(line: str, idx: int) -> Optional[object]:
            if _COMMENT_RE.match(line):
                return None
            if _TX_ORIGIN_RE.search(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "tx-origin",
                    0.75,
                    "MEDIUM",
                    "CWE-807",
                    "Authorisation uses tx.origin, which a malicious intermediary "
                    "contract can spoof by calling through the owner.",
                    "Authorise on msg.sender; never use tx.origin for access control.",
                )
            if _DELEGATECALL_RE.search(line) and not _CONSTANT_TARGET_RE.search(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "controlled-delegatecall",
                    0.8,
                    "HIGH",
                    "CWE-829",
                    "delegatecall runs foreign bytecode in this contract's storage "
                    "context, so a controlled target can overwrite state or drain funds.",
                    "Restrict delegatecall targets to a hardcoded, audited set and "
                    "verify the implementation contract before delegating.",
                )
            if _WEAK_RNG_RE.search(line) and _MODULO_RE.search(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "weak-prng",
                    0.8,
                    "HIGH",
                    "CWE-330",
                    "Randomness is derived from block state, which validators can "
                    "influence, making the outcome predictable.",
                    "Use a verifiable randomness oracle (e.g. Chainlink VRF) or a "
                    "commit-reveal scheme.",
                )
            if _DEADLINE_RE.search(line) and _WEAK_RNG_RE.search(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "timestamp-dependency",
                    0.6,
                    "MEDIUM",
                    "CWE-349",
                    "Deadline logic depends on block.timestamp, which a validator can "
                    "shift by seconds, altering settlement outcomes.",
                    "Bound the acceptable drift explicitly or rely on an oracle timestamp.",
                )
            if _SELFDESTRUCT_RE.search(line):
                sev = "HIGH" if _UPGRADEABLE_RE.search(code) else "MEDIUM"
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "unprotected-upgrade",
                    0.7,
                    sev,
                    "CWE-506",
                    "selfdestruct is reachable; in an upgradeable contract an "
                    "uninitialised logic contract can be destroyed by anyone.",
                    "Remove selfdestruct, or gate it behind an initialised owner check "
                    "on the logic contract.",
                )
            if _POW_RE.search(line) and not _POW_LITERAL_RE.search(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "incorrect-exp",
                    0.6,
                    "MEDIUM",
                    "CWE-682",
                    "Exponentiation with a variable right operand, where the operands "
                    "are easily transposed and the result overflows for large inputs.",
                    "Use a constant exponent, or exp() from OpenZeppelin with an explicit "
                    "overflow check.",
                )
            if _DIV_THEN_MUL_RE.search(line) and not _COMMENT_RE.match(line):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "divide-before-multiply",
                    0.55,
                    "MEDIUM",
                    "CWE-682",
                    "Division before multiplication truncates intermediate precision, so "
                    "the computed amount is systematically lower than intended.",
                    "Multiply before dividing, or use mulDiv with full-precision math.",
                )
            if _ERC20_RETURN_RE.search(line) and not _SAFE_ERC20_RE.search(code):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "unchecked-transfer",
                    0.7,
                    "HIGH",
                    "CWE-252",
                    "ERC20 transfer return value is ignored; a token that returns false "
                    "instead of reverting makes the transfer silently fail.",
                    "Use OpenZeppelin SafeERC20 (safeTransfer/safeTransferFrom) or check "
                    "the returned boolean.",
                )
            if (
                _BARE_CALL_RE.search(line)
                and not _ASSIGNED_CALL_RE.search(line)
                and not _GUARDED_RE.search(line)
            ):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "unchecked-lowlevel",
                    0.7,
                    "MEDIUM",
                    "CWE-252",
                    "Low-level call result is discarded, so a failed call is "
                    "indistinguishable from a successful one.",
                    "Capture the boolean and revert on failure.",
                )
            if (
                _PRIVATE_KEY_RE.search(line)
                and _KEY_CONTEXT_RE.search(line)
                and not _PLACEHOLDER_RE.search(line)
            ):
                return make_finding(
                    path,
                    idx,
                    VULN_TYPE,
                    "hardcoded-private-key",
                    0.9,
                    "CRITICAL",
                    "CWE-798",
                    "A 32-byte private key is embedded in source, giving anyone with "
                    "repository or bytecode access full control of the signing identity.",
                    "Revoke and rotate the key immediately, keep signing keys in an HSM "
                    "or managed signer, and purge the value from git history.",
                )
            return None

        return scan_lines(code, path, check)

    # ------------------------------------------------------------------
    # Pre-0.8 arithmetic
    # ------------------------------------------------------------------

    def _overflow(self, code: str, path) -> List:
        pragma = _PRAGMA_RE.search(code)
        if not pragma or _SAFEMATH_RE.search(code):
            return []
        versions = re.findall(r"(\d+)\.(\d+)(?:\.(\d+))?", pragma.group(1))
        if not versions:
            return []
        major, minor = int(versions[0][0]), int(versions[0][1])
        if (major, minor) >= (0, 8):
            return []

        def check(line: str, idx: int) -> Optional[object]:
            if _COMMENT_RE.match(line) or not _ARITH_RE.search(line):
                return None
            if "require(" in line or "assert(" in line:
                return None
            return make_finding(
                path,
                idx,
                VULN_TYPE,
                "integer-overflow",
                0.55,
                "MEDIUM",
                "CWE-190",
                "Arithmetic on solc < 0.8 wraps silently on overflow, so balance and "
                "share calculations can be inverted by crafted inputs.",
                "Compile with solc >= 0.8, or wrap arithmetic in SafeMath and bound "
                "user-supplied values.",
            )

        return scan_lines(code, path, check)
