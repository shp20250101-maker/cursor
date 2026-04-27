"""EVM executor on top of eth_tester / py-evm.

For each test case we:
  1. snapshot the chain
  2. deploy the contract (once per ``EVMExecutor`` instance, then snapshot
     before each test)
  3. send each call as a transaction; record gas used, revert reason,
     emitted logs, and coverage sites/branches
  4. revert the snapshot so subsequent tests start from the same state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from eth_tester import EthereumTester, PyEVMBackend
from eth_utils import to_checksum_address
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

from .coverage import CoverageTracker, CoverageInstrumenter
from .corpus import Call, TestCase
from ..static_analysis.analyzer import ContractInfo, FunctionInfo

logger = logging.getLogger(__name__)


@dataclass
class CallTrace:
    function: str
    caller: str
    args: list[Any]
    value: int
    success: bool
    gas_used: int
    revert_reason: str = ""
    return_data: bytes = b""
    logs: list[dict] = field(default_factory=list)


@dataclass
class ExecutionResult:
    test_case: TestCase
    traces: list[CallTrace]
    new_pc_sites: int
    new_branches: int
    error: str | None = None
    bug_findings: list[dict] = field(default_factory=list)
    balance_before: int = 0
    balance_after: int = 0
    caller_balances_before: dict[str, int] = field(default_factory=dict)
    caller_balances_after: dict[str, int] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.error is None and any(t.success for t in self.traces)


class EVMExecutor:
    def __init__(
        self,
        contract: ContractInfo,
        deployer: str | None = None,
        accounts: list[str] | None = None,
        constructor_args: list[Any] | None = None,
        constructor_value: int = 0,
        seed_balance_wei: int = 10**24,
    ):
        self.contract = contract
        self.tester = EthereumTester(backend=PyEVMBackend())
        self.w3 = Web3(EthereumTesterProvider(self.tester))

        self.accounts = list(accounts) if accounts else list(self.w3.eth.accounts[:5])
        self.deployer = deployer or self.accounts[0]

        for a in self.accounts:
            try:
                if self.w3.eth.get_balance(a) < seed_balance_wei // 2:
                    self.tester.send_transaction(
                        {"from": self.w3.eth.accounts[0], "to": a, "value": seed_balance_wei, "gas": 21000}
                    )
            except Exception:
                pass

        self.tracker = CoverageTracker()
        self._computation_class = self._discover_computation_class()

        self.contract_abi = contract.abi
        self.contract_address: str | None = None
        self._post_deploy_snapshot: Any = None

        self.deploy(constructor_args or [], value=constructor_value)

    # ------------------------------------------------------------------

    def _discover_computation_class(self):
        chain = self.tester.backend.chain
        vm = chain.get_vm()
        state_cls = vm._state_class
        return state_cls.computation_class

    # ------------------------------------------------------------------

    def deploy(self, constructor_args: list[Any], value: int = 0) -> str:
        Contract = self.w3.eth.contract(abi=self.contract_abi, bytecode=self.contract.bytecode)
        with CoverageInstrumenter(self._computation_class, self.tracker):
            tx_hash = Contract.constructor(*constructor_args).transact(
                {"from": self.deployer, "gas": 8_000_000, "value": value}
            )
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        if receipt["status"] != 1 or not receipt.contractAddress:
            raise RuntimeError(
                f"Contract deployment failed (status={receipt['status']})"
            )
        self.contract_address = receipt.contractAddress
        self._post_deploy_snapshot = self.tester.take_snapshot()
        return self.contract_address

    # ------------------------------------------------------------------

    def execute(self, tc: TestCase) -> ExecutionResult:
        assert self.contract_address is not None
        snap = self.tester.take_snapshot()
        traces: list[CallTrace] = []
        error: str | None = None

        before_pc = len(self.tracker.pc_sites)
        before_br = len(self.tracker.branch_edges)

        contract = self.w3.eth.contract(address=self.contract_address, abi=self.contract_abi)

        contract_balance_before = self.w3.eth.get_balance(self.contract_address)
        caller_balances_before: dict[str, int] = {}
        for c in tc.calls:
            addr = _normalize_addr(c.caller, self.accounts[0])
            if addr not in caller_balances_before:
                caller_balances_before[addr] = self.w3.eth.get_balance(addr)

        try:
            with CoverageInstrumenter(self._computation_class, self.tracker):
                for call in tc.calls:
                    trace = self._send_call(contract, call)
                    traces.append(trace)
        except Exception as exc:  # pragma: no cover - defensive
            error = f"executor error: {exc}"
            logger.exception("executor error: %s", exc)

        contract_balance_after = self.w3.eth.get_balance(self.contract_address)
        caller_balances_after = {
            a: self.w3.eth.get_balance(a) for a in caller_balances_before
        }

        try:
            self.tester.revert_to_snapshot(snap)
        except Exception:
            self.tester.revert_to_snapshot(self._post_deploy_snapshot)

        new_pc = len(self.tracker.pc_sites) - before_pc
        new_br = len(self.tracker.branch_edges) - before_br
        return ExecutionResult(
            test_case=tc,
            traces=traces,
            new_pc_sites=new_pc,
            new_branches=new_br,
            error=error,
            balance_before=contract_balance_before,
            balance_after=contract_balance_after,
            caller_balances_before=caller_balances_before,
            caller_balances_after=caller_balances_after,
        )

    # ------------------------------------------------------------------

    def _send_call(self, contract, call: Call) -> CallTrace:
        fn_info = next(
            (f for f in self.contract.functions if f.name == call.function), None
        )

        caller = _normalize_addr(call.caller, self.accounts[0])
        value = max(0, int(call.value or 0))
        if fn_info is None or fn_info.kind == "fallback" or fn_info.kind == "receive":
            return self._send_raw(caller, value, b"")

        try:
            fn = contract.get_function_by_name(call.function)
        except Exception:
            try:
                fn = contract.find_functions_by_name(call.function)[0]
            except Exception:
                return CallTrace(
                    function=call.function, caller=caller, args=call.args, value=value,
                    success=False, gas_used=0, revert_reason=f"unknown function {call.function}",
                )
        args = _coerce_args(fn_info, call.args)
        try:
            tx_hash = fn(*args).transact(
                {"from": caller, "gas": 6_000_000, "value": value}
            )
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        except Exception as exc:
            return CallTrace(
                function=call.function, caller=caller, args=args, value=value,
                success=False, gas_used=0, revert_reason=f"tx error: {exc}",
            )
        success = receipt["status"] == 1
        logs = [dict(l) for l in receipt.get("logs", [])]
        return CallTrace(
            function=call.function,
            caller=caller,
            args=args,
            value=value,
            success=success,
            gas_used=receipt.get("gasUsed", 0),
            revert_reason="" if success else "revert",
            logs=logs,
        )

    def _send_raw(self, caller: str, value: int, data: bytes) -> CallTrace:
        try:
            tx = {
                "from": caller,
                "to": self.contract_address,
                "value": value,
                "gas": 1_000_000,
                "data": "0x" + data.hex(),
            }
            tx_hash = self.w3.eth.send_transaction(tx)
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            return CallTrace(
                function="<raw>",
                caller=caller,
                args=[],
                value=value,
                success=receipt["status"] == 1,
                gas_used=receipt.get("gasUsed", 0),
            )
        except Exception as exc:
            return CallTrace(
                function="<raw>", caller=caller, args=[], value=value,
                success=False, gas_used=0, revert_reason=str(exc),
            )

    # ------------------------------------------------------------------

    def get_storage(self, slot: int) -> int:
        if not self.contract_address:
            return 0
        try:
            v = self.w3.eth.get_storage_at(self.contract_address, slot)
            return int.from_bytes(v, "big")
        except Exception:
            return 0


def _normalize_addr(addr: str, fallback: str) -> str:
    try:
        return to_checksum_address(addr)
    except Exception:
        return fallback


def _coerce_args(fn: FunctionInfo, args: list[Any]) -> list[Any]:
    out = []
    for i, expected in enumerate(fn.inputs):
        if i >= len(args):
            out.append(_zero_for(expected["type"]))
            continue
        v = args[i]
        out.append(_coerce(v, expected["type"]))
    return out


def _coerce(v: Any, sol_type: str) -> Any:
    if sol_type == "address":
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            try:
                return to_checksum_address(v)
            except Exception:
                return to_checksum_address("0x" + "0" * 40)
        return to_checksum_address("0x" + "0" * 40)
    if sol_type == "bool":
        return bool(v)
    if sol_type.startswith("uint") or sol_type.startswith("int"):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    if sol_type == "bytes":
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, str):
            try:
                return bytes.fromhex(v[2:] if v.startswith("0x") else v)
            except ValueError:
                return v.encode()
        return b""
    if sol_type.startswith("bytes"):
        n = int(sol_type[len("bytes"):])
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
        elif isinstance(v, str):
            try:
                b = bytes.fromhex(v[2:] if v.startswith("0x") else v)
            except ValueError:
                b = v.encode()
        else:
            b = b""
        if len(b) > n:
            b = b[:n]
        return b.ljust(n, b"\x00")
    if sol_type == "string":
        return v if isinstance(v, str) else str(v)
    if sol_type.endswith("[]"):
        base = sol_type[:-2]
        if not isinstance(v, list):
            return []
        return [_coerce(x, base) for x in v]
    return v


def _zero_for(sol_type: str) -> Any:
    if sol_type == "address":
        return to_checksum_address("0x" + "0" * 40)
    if sol_type == "bool":
        return False
    if sol_type.startswith("uint") or sol_type.startswith("int"):
        return 0
    if sol_type == "bytes":
        return b""
    if sol_type.startswith("bytes"):
        n = int(sol_type[len("bytes"):])
        return b"\x00" * n
    if sol_type == "string":
        return ""
    if sol_type.endswith("[]"):
        return []
    return 0
