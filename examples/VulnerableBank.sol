// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A deliberately vulnerable bank used to demonstrate EchoFuzz.
///
/// The contract contains the following bugs that EchoFuzz's chain-guided
/// VFCS + iterative feedback should rediscover:
///
///   * `setAdmin` has no access control: any address can take ownership.
///   * `withdrawAll` lets the admin drain *every* user's funds.
///   * `unsafeTransfer` performs an unchecked low-level call.
///   * `assertInvariant` exposes a state assertion that can be falsified
///     after a certain combination of deposits/withdrawals.
contract VulnerableBank {
    address public admin;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposit(address indexed from, uint256 amount);
    event Withdraw(address indexed to, uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        emit Withdraw(msg.sender, amount);
    }

    /// BUG: missing access control.
    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }

    /// BUG: admin can drain all user balances regardless of ownership.
    function withdrawAll() external {
        require(msg.sender == admin, "not admin");
        uint256 bal = address(this).balance;
        (bool ok, ) = admin.call{value: bal}("");
        require(ok, "send failed");
        totalDeposits = 0;
    }

    /// BUG: low-level call return value is ignored.
    function unsafeTransfer(address payable to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        to.call{value: amount}("");
    }

    /// Triggers a Panic(0x01) when the invariant is violated. EchoFuzz's
    /// AssertionOracle reports such reverts as findings.
    function assertInvariant() external view {
        assert(totalDeposits <= address(this).balance);
    }
}
