// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Single planted defect: authorization on tx.origin, which a malicious
/// intermediary contract can spoof by routing the call through the admin.
contract AuthGate {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function setAdmin(address next) external {
        require(tx.origin == admin);
        admin = next;
    }
}
