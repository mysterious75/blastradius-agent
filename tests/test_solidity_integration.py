"""End-to-end wiring: a real .sol file in a repo must reach SolidityScanner
through CVEHunter's file iteration and scan path, not just via direct
scanner instantiation. Offline, temporary directory only.
"""

from pathlib import Path

from blastradius.hunter.scanner import FILE_EXTENSIONS, CVEHunter

VULNERABLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public total;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
        total = total + amount;
    }

    function authorize() public view {
        require(tx.origin == owner);
    }

    function payout(address payable to, uint256 amount) public {
        to.transfer(amount);
    }
}
"""

CLEAN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract SafeVault {
    using SafeERC20 for IERC20;
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public total;
    IERC20 public token;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        total = total - amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function collect(address asset, address to, uint256 amount) external {
        require(msg.sender == owner);
        token.safeTransfer(to, amount);
    }
}
"""


def _scan(tmp_path: Path, name: str, body: str):
    (tmp_path / name).write_text(body, encoding="utf-8")
    hunter = CVEHunter()
    return hunter, list(hunter._iter_files(str(tmp_path))), hunter._scan_file(tmp_path / name)


def test_sol_extension_is_registered():
    assert "*.sol" in FILE_EXTENSIONS


def test_iter_files_yields_sol(tmp_path):
    hunter, found, _ = _scan(tmp_path, "Vault.sol", VULNERABLE)
    assert any(p.suffix == ".sol" for p in found), "*.sol never reached the hunter"


def test_hunter_scan_reports_solidity_findings(tmp_path):
    _, _, findings = _scan(tmp_path, "Vault.sol", VULNERABLE)
    classes = {f.payload for f in findings}
    assert findings, "no findings from vulnerable contract"
    assert "tx-origin" in classes
    assert "arbitrary-send" in classes
    assert "reentrancy" in classes
    assert all(f.vuln_type == "solidity" for f in findings)


def test_hunter_scan_respects_reentrancy_guard(tmp_path):
    _, _, findings = _scan(tmp_path, "SafeVault.sol", CLEAN)
    classes = {f.payload for f in findings}
    assert "reentrancy" not in classes
    assert "tx-origin" not in classes
    assert "arbitrary-send" not in classes
    assert "unchecked-transfer" not in classes


def test_findings_carry_reporting_metadata(tmp_path):
    _, _, findings = _scan(tmp_path, "Vault.sol", VULNERABLE)
    for f in findings:
        assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f.cwe.startswith("CWE-")
        assert f.description and f.remediation
        assert 0 < f.confidence <= 1
        assert f.file.endswith("Vault.sol")
        assert f.line >= 1
