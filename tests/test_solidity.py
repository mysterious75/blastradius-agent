"""SolidityScanner tests — offline fixtures, no solc toolchain required."""

import pytest

from blastradius.scanners.solidity import SolidityScanner

HEAD = "pragma solidity ^0.8.20;\ncontract V {\n"


def classes(findings):
    return {f.payload for f in findings}


def scan(body: str, head: str = HEAD):
    return SolidityScanner().detect(head + body + "\n}\n", "V.sol")


# ------------------------------------------------------------- dispatch


def test_ignores_non_solidity():
    assert SolidityScanner().detect("def foo():\n    return 1\n", "a.py") == []


def test_ignores_empty():
    assert SolidityScanner().detect("", "a.sol") == []


def test_line_numbers_are_sol_file_lines():
    findings = scan("  function auth() public { require(tx.origin == owner); }")
    hit = [f for f in findings if f.payload == "tx-origin"]
    assert len(hit) == 1
    assert hit[0].line == 3


# ------------------------------------------------------------- reentrancy


def test_reentrancy_external_call_then_state_write():
    findings = scan(
        "  function w(uint amt) external {\n"
        '    (bool ok,) = msg.sender.call{value: amt}("");\n'
        "    require(ok);\n"
        "    total = total + amt;\n"
        "  }"
    )
    assert "reentrancy" in classes(findings)
    hit = [f for f in findings if f.payload == "reentrancy"][0]
    assert hit.severity == "HIGH"
    assert hit.confidence >= 0.8


def test_reentrancy_downgraded_when_guarded():
    findings = scan(
        "  function w(uint amt) external nonReentrant {\n"
        '    (bool ok,) = msg.sender.call{value: amt}("");\n'
        "    require(ok);\n"
        "    total = total + amt;\n"
        "  }"
    )
    hit = [f for f in findings if f.payload == "reentrancy"][0]
    assert hit.severity == "MEDIUM"


def test_reentrancy_not_reported_when_state_written_first():
    findings = scan(
        "  function w(uint amt) external {\n"
        "    total = total - amt;\n"
        '    (bool ok,) = msg.sender.call{value: amt}("");\n'
        "    require(ok);\n"
        "  }"
    )
    assert "reentrancy" not in classes(findings)


def test_reentrancy_ignores_view_call():
    """staticcall hands over no value, so it is not a drain primitive."""
    findings = scan(
        "  function w(uint amt) external {\n"
        "    oracle.staticcall(abi.encode(amt));\n"
        "    total = total + amt;\n"
        "  }"
    )
    assert "reentrancy" not in classes(findings)


# ------------------------------------------------------------- auth / call


def test_tx_origin():
    assert "tx-origin" in classes(scan("  function a() public { require(tx.origin == o); }"))


def test_delegatecall_controlled_target():
    assert "controlled-delegatecall" in classes(
        scan("  function a(address impl) public { impl.delegatecall(d); }")
    )


def test_delegatecall_constant_target_allowed():
    assert "controlled-delegatecall" not in classes(
        scan(
            "  function a() public { IT(0x1234567890123456789012345678901234567890).delegatecall(d); }"
        )
    )


def test_arbitrary_send_to_param():
    assert "arbitrary-send" in classes(
        scan("  function pay(address payable to) public { to.transfer(amt); }")
    )


def test_arbitrary_send_call_value_to_param():
    assert "arbitrary-send" in classes(
        scan('  function pay(address to) public { to.call{value: amt}(""); }')
    )


def test_send_to_state_var_not_flagged():
    assert "arbitrary-send" not in classes(scan("  function pay() public { owner.transfer(amt); }"))


# ------------------------------------------------------------- randomness / time


def test_weak_prng():
    assert "weak-prng" in classes(
        scan("  function r() public view returns (uint) { return uint(block.timestamp % 7); }")
    )


def test_blockhash_prng():
    assert "weak-prng" in classes(
        scan("  function r() public view returns (uint) { return uint(blockhash(1) % 7); }")
    )


def test_timestamp_deadline():
    assert "timestamp-dependency" in classes(
        scan("  uint deadline; function c() public { require(block.timestamp < deadline); }")
    )


# ------------------------------------------------------------- calls / math


def test_unchecked_lowlevel():
    assert "unchecked-lowlevel" in classes(scan('  function a(address t) public { t.call(""); }'))


def test_checked_lowlevel_not_flagged():
    assert "unchecked-lowlevel" not in classes(
        scan('  function a(address t) public { (bool ok,) = t.call(""); require(ok); }')
    )


def test_unchecked_erc20_transfer():
    findings = scan("  function a(IERC20 tk, address to) public { tk.transfer(to, amt); }")
    assert "unchecked-transfer" in classes(findings)


def test_safe_erc20_not_flagged():
    src = (
        "import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';\n"
        "using SafeERC20 for IERC20;\n"
        + HEAD
        + "  function a(IERC20 tk, address to) public { tk.safeTransfer(to, amt); }\n}\n"
    )
    assert "unchecked-transfer" not in classes(SolidityScanner().detect(src, "V.sol"))


def test_divide_before_multiply():
    assert "divide-before-multiply" in classes(
        scan("  function a() public pure returns (uint) { return (x / y) * z; }")
    )


def test_incorrect_exp():
    assert "incorrect-exp" in classes(
        scan("  function a(uint e) public pure returns (uint) { return 2 ** e; }")
    )


def test_literal_exp_not_flagged():
    assert "incorrect-exp" not in classes(
        scan("  function a() public pure returns (uint) { return 2 ** 8; }")
    )


def test_selfdestruct_in_upgradeable_contract_is_high():
    src = (
        "pragma solidity ^0.8.20;\n"
        "contract L is Initializable {\n"
        "  function init() public initializer {}\n"
        "  function dead() public { selfdestruct(payable(msg.sender)); }\n"
        "}\n"
    )
    hit = [f for f in SolidityScanner().detect(src, "L.sol") if f.payload == "unprotected-upgrade"]
    assert hit and hit[0].severity == "HIGH"


# ------------------------------------------------------------- overflow

LEGACY = "pragma solidity ^0.7.6;\ncontract V {\n"


def test_pre_08_arithmetic_flagged():
    findings = SolidityScanner().detect(
        LEGACY + "  function a(uint x) public { y = x * 2; }\n}\n", "V.sol"
    )
    assert "integer-overflow" in classes(findings)


def test_pre_08_with_safemath_clean():
    src = LEGACY + "  using SafeMath for uint;\n  function a(uint x) public { y = x.mul(2); }\n}\n"
    assert "integer-overflow" not in classes(SolidityScanner().detect(src, "V.sol"))


def test_solc_08_arithmetic_clean():
    assert "integer-overflow" not in classes(scan("  function a(uint x) public { y = x * 2; }"))


# ------------------------------------------------------------- secrets


def test_hardcoded_private_key():
    key = "7a3f" * 16
    assert len(key) == 64
    findings = scan(f"  uint256 privateKey = 0x{key};")
    hit = [f for f in findings if f.payload == "hardcoded-private-key"]
    assert hit and hit[0].severity == "CRITICAL"


def test_placeholder_key_ignored():
    assert "hardcoded-private-key" not in classes(scan(f"  uint256 privateKey = 0x{'0' * 64};"))


def test_64hex_without_key_context_ignored():
    src = HEAD + f"  bytes32 root = 0x{'ab' * 32};\n" + "  uint amt; uint y;\n}\n"
    assert "hardcoded-private-key" not in classes(SolidityScanner().detect(src, "V.sol"))


# ------------------------------------------------------------- registry


def test_registered_in_hunter_registry():
    import blastradius.hunter.scanner as S
    from blastradius.hunter.scanner import CVEHunter

    assert "solidity" in S.VULN_META
    assert "solidity" in S.VALID_VULN_TYPES
    assert CVEHunter._title("solidity") != "solidity"
    assert S.VULN_META["solidity"]["cvss"] > 0


@pytest.mark.parametrize("path", ["a.sol", "src/Vault.sol"])
def test_path_preserved(path):
    findings = SolidityScanner().detect(
        HEAD + "  function a() public { require(tx.origin == o); }\n}\n", path
    )
    assert all(f.file.endswith(path) for f in findings)
