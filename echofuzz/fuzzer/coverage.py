"""EVM-level coverage tracking via opcode hooks.

We patch the running VM's computation-class ``opcodes`` mapping so that
each executed opcode emits a ``(code_address, pc, opcode)`` site to a
shared :class:`CoverageTracker`.

For JUMPI we additionally record the post-execution PC so we can tell
the *taken* branch apart from the *fall-through* branch -- the standard
edge / branch-coverage signal used by greybox fuzzers.

The hooks impose a per-opcode Python overhead but the VM is already
executed in pure Python, so the practical slowdown is modest.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


JUMPI = 0x57
JUMPDEST = 0x5B


@dataclass
class CoverageTracker:
    pc_sites: set[tuple[bytes, int]] = field(default_factory=set)
    branch_edges: set[tuple[bytes, int, int]] = field(default_factory=set)  # (addr, jumpi_pc, post_pc)
    opcode_counts: dict[int, int] = field(default_factory=dict)
    last_trace: list[tuple[int, int]] = field(default_factory=list)  # (pc, opcode)
    record_trace: bool = False
    enabled: bool = False

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def reset_trace(self) -> None:
        self.last_trace = []

    def record(self, code_address: bytes, pc: int, opcode: int) -> None:
        if not self.enabled:
            return
        site = (code_address, pc)
        self.pc_sites.add(site)
        self.opcode_counts[opcode] = self.opcode_counts.get(opcode, 0) + 1
        if self.record_trace:
            self.last_trace.append((pc, opcode))

    def record_branch(
        self, code_address: bytes, jumpi_pc: int, post_pc: int
    ) -> None:
        if not self.enabled:
            return
        self.branch_edges.add((code_address, jumpi_pc, post_pc))

    def snapshot_size(self) -> int:
        return len(self.pc_sites) + len(self.branch_edges)


class CoverageInstrumenter:
    """Patch a computation class' opcodes dict in place.

    Use as a context manager that activates the global tracker:

        with CoverageInstrumenter(state_class, tracker):
            ...run transactions...
    """

    def __init__(self, computation_class, tracker: CoverageTracker):
        self.computation_class = computation_class
        self.tracker = tracker
        self._original: dict[int, Any] | None = None

    def __enter__(self) -> "CoverageInstrumenter":
        if self._original is not None:
            return self
        self._original = dict(self.computation_class.opcodes)
        wrapped: dict[int, Any] = {}
        tracker = self.tracker
        for op_byte, op in self._original.items():
            wrapped[op_byte] = _wrap_opcode(op, op_byte, tracker)
        self.computation_class.opcodes = wrapped
        tracker.enabled = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._original is None:
            return
        self.computation_class.opcodes = self._original
        self._original = None
        self.tracker.enabled = False


def _wrap_opcode(opcode_obj, op_byte: int, tracker: CoverageTracker):
    is_jumpi = op_byte == JUMPI

    def wrapped(computation):
        # ``computation.code.program_counter`` already points to the byte
        # right after the opcode (the iterator pre-advanced it). The
        # opcode's own pc is therefore one byte earlier.
        pc = max(0, computation.code.program_counter - 1)
        addr = bytes(computation.msg.code_address)
        tracker.record(addr, pc, op_byte)
        result = opcode_obj(computation)
        if is_jumpi:
            post_pc = computation.code.program_counter
            tracker.record_branch(addr, pc, post_pc)
        return result

    # Preserve mnemonic / gas_cost attributes for the rare debug code paths.
    for attr in ("mnemonic", "gas_cost", "logic_fn"):
        if hasattr(opcode_obj, attr):
            try:
                setattr(wrapped, attr, getattr(opcode_obj, attr))
            except (AttributeError, TypeError):
                pass
    return wrapped
