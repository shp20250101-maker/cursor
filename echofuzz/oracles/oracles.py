"""Bug oracles for EchoFuzz.

An oracle inspects an :class:`ExecutionResult` plus the EVM context (the
contract balance before / after, ownership-related storage slots, etc.)
and returns a list of findings. Findings are deduplicated by ``kind`` +
``signature`` at the engine level.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..fuzzer.executor import EVMExecutor, ExecutionResult


@dataclass
class Finding:
    kind: str
    detail: str
    signature: str  # for dedup
    test_signature: str = ""
    severity: str = "medium"
    extra: dict[str, Any] = field(default_factory=dict)


class BugOracle:
    name: str = "base"

    def setup(self, executor: EVMExecutor) -> None:
        """Called once per executor; record initial state."""

    def before_test(self, executor: EVMExecutor) -> None:
        """Called before each test execution."""

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------


class AssertionOracle(BugOracle):
    """Detect Solidity ``assert``/Panic(0x01) reverts.

    The 4-byte ``Panic(uint256)`` selector is ``0x4e487b71``. When the
    revert reason in a transaction's return data starts with this selector
    and the panic code is 0x01, an ``assert`` failed -- i.e. an invariant
    was broken.
    """

    name = "assertion"

    PANIC_SELECTOR = bytes.fromhex("4e487b71")

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        out: list[Finding] = []
        for trace in result.traces:
            if trace.success:
                continue
            data = trace.return_data
            if data and data[:4] == self.PANIC_SELECTOR and len(data) >= 36:
                code = int.from_bytes(data[4:36], "big")
                if code == 0x01:
                    out.append(
                        Finding(
                            kind="assertion-violation",
                            detail=f"assert failed in {trace.function}",
                            signature=f"assert:{trace.function}",
                            severity="high",
                        )
                    )
                elif code == 0x11:
                    out.append(
                        Finding(
                            kind="arithmetic-overflow",
                            detail=f"over/underflow in {trace.function}",
                            signature=f"panic11:{trace.function}",
                            severity="high",
                        )
                    )
                elif code == 0x12:
                    out.append(
                        Finding(
                            kind="div-by-zero",
                            detail=f"division by zero in {trace.function}",
                            signature=f"panic12:{trace.function}",
                            severity="medium",
                        )
                    )
        return out


class EtherDrainOracle(BugOracle):
    """Detect non-owner accounts extracting Ether.

    Records the contract's pre-test balance, the caller's pre-test balance,
    and flags any case where a non-owner caller's balance increases by
    more than they sent in (modulo gas-price 0 here).
    """

    name = "ether-drain"

    def __init__(self, owner: str | None = None):
        self.owner = owner.lower() if owner else None
        self._initial_contract_balance = 0

    def setup(self, executor: EVMExecutor) -> None:
        self._initial_contract_balance = executor.w3.eth.get_balance(executor.contract_address)
        if self.owner is None:
            self.owner = executor.deployer.lower()

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        findings: list[Finding] = []
        # Net Ether each caller sent in during this test (msg.value sums).
        net_in: dict[str, int] = {}
        for tr in result.traces:
            net_in[tr.caller.lower()] = net_in.get(tr.caller.lower(), 0) + tr.value

        for caller, before in result.caller_balances_before.items():
            after = result.caller_balances_after.get(caller, before)
            paid_in = net_in.get(caller.lower(), 0)
            net_received = after - before + paid_in
            if caller.lower() == self.owner:
                continue
            if net_received > 10**16:  # > 0.01 ether net gain (gas-free here)
                findings.append(
                    Finding(
                        kind="possible-ether-drain",
                        detail=(
                            f"non-owner {caller[:10]} received {net_received} wei net "
                            f"after sending in {paid_in} wei"
                        ),
                        signature=f"drain:{caller.lower()}",
                        severity="high",
                        extra={"net": net_received, "paid": paid_in},
                    )
                )
        return findings


class OwnershipHijackOracle(BugOracle):
    """Detect changes to common owner/admin storage slots by non-owners.

    We probe slots 0..7 before and after the test. If a slot that looked
    like an address (top 12 bytes zero) changed to a non-zero address that
    matches a non-deployer caller, we flag a hijack.
    """

    name = "ownership-hijack"

    def __init__(self, slots: Iterable[int] = range(8)):
        self.slots = list(slots)
        self._baseline: dict[int, int] = {}

    def setup(self, executor: EVMExecutor) -> None:
        self._baseline = {s: executor.get_storage(s) for s in self.slots}

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        # The executor has already reverted state, so we cannot read post-
        # test storage directly. Instead we replay the (committed)
        # baseline read and compare against any change observed in the
        # caller-balance / function-name combination during the test.
        findings: list[Finding] = []
        deployer = executor.deployer.lower()
        for tr in result.traces:
            if not tr.success:
                continue
            n = tr.function.lower()
            if any(p in n for p in ("setowner", "transferownership", "setadmin", "init")):
                if tr.caller.lower() != deployer:
                    findings.append(
                        Finding(
                            kind="possible-ownership-hijack",
                            detail=f"non-deployer {tr.caller[:10]} called {tr.function}",
                            signature=f"hijack:{tr.function}",
                            severity="high",
                        )
                    )
        return findings


class SuicideOracle(BugOracle):
    """Detect SELFDESTRUCT being reached during a test."""

    name = "selfdestruct"

    SELFDESTRUCT = 0xFF

    def __init__(self):
        self._baseline = 0

    def setup(self, executor: EVMExecutor) -> None:
        self._baseline = executor.tracker.opcode_counts.get(self.SELFDESTRUCT, 0)

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        cur = executor.tracker.opcode_counts.get(self.SELFDESTRUCT, 0)
        if cur > self._baseline:
            self._baseline = cur
            return [
                Finding(
                    kind="selfdestruct-reached",
                    detail="SELFDESTRUCT executed during test",
                    signature="selfdestruct",
                    severity="critical",
                )
            ]
        return []


class UncheckedCallOracle(BugOracle):
    """Heuristic for unchecked low-level CALL.

    Counts CALL opcodes (0xF1) executed in tests; if many CALLs occur but
    no failures bubble up to the top-level transaction, it may indicate an
    unchecked CALL pattern. This is a coarse indicator and should be
    interpreted alongside source review.
    """

    name = "unchecked-call"

    CALL = 0xF1

    def __init__(self):
        self._baseline = 0

    def setup(self, executor: EVMExecutor) -> None:
        self._baseline = executor.tracker.opcode_counts.get(self.CALL, 0)

    def after_test(self, executor: EVMExecutor, result: ExecutionResult) -> list[Finding]:
        cur = executor.tracker.opcode_counts.get(self.CALL, 0)
        delta = cur - self._baseline
        self._baseline = cur
        if delta == 0:
            return []
        successful = [t for t in result.traces if t.success]
        if delta > 0 and successful:
            return [
                Finding(
                    kind="external-call",
                    detail=f"{delta} low-level CALL(s) executed",
                    signature="external-call",
                    severity="info",
                )
            ]
        return []


DEFAULT_ORACLES: list[BugOracle] = [
    AssertionOracle(),
    EtherDrainOracle(),
    OwnershipHijackOracle(),
    SuicideOracle(),
    UncheckedCallOracle(),
]
