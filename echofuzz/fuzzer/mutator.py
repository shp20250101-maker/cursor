"""ABI-aware test input generator and mutator."""

from __future__ import annotations

import os
import random
import string
from dataclasses import dataclass
from typing import Any

from ..static_analysis.analyzer import FunctionInfo
from ..vfcs.generator import ArgumentHint


_INTEREST_UINT = [0, 1, 2, 3, 7, 8, 31, 32, 127, 128, 255, 256, 65535, 2**32 - 1, 2**64 - 1, 2**128 - 1, 2**160, 2**256 - 1]
_INTEREST_ADDR = [
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0x00000000000000000000000000000000000000ff",
    "0xffffffffffffffffffffffffffffffffffffffff",
]
_INTEREST_BYTES = [b"", b"\x00", b"\xff", b"\x00" * 32, b"\xff" * 32]


@dataclass
class MutatorConfig:
    seed: int | None = None
    bias_interesting: float = 0.6  # probability to draw from interesting values


class ABIMutator:
    def __init__(
        self,
        functions: list[FunctionInfo],
        attacker_addrs: list[str] | None = None,
        config: MutatorConfig | None = None,
    ):
        self.functions = {f.name: f for f in functions}
        self.attacker_addrs = attacker_addrs or []
        self.cfg = config or MutatorConfig()
        self.rng = random.Random(self.cfg.seed)
        self.hints: dict[str, ArgumentHint] = {}

    def update_hints(self, hints: list[ArgumentHint]) -> None:
        for h in hints:
            existing = self.hints.get(h.function)
            if existing is None:
                self.hints[h.function] = h
            else:
                for k, v in h.values.items():
                    existing.values.setdefault(k, []).extend(v)

    # ------------------------------------------------------------------

    def fresh_args(self, fn: FunctionInfo) -> list[Any]:
        return [self._gen(p["type"], fn.name, p.get("name", "")) for p in fn.inputs]

    def mutate_args(self, fn: FunctionInfo, args: list[Any]) -> list[Any]:
        if not args:
            return args
        out = list(args)
        idx = self.rng.randrange(len(out))
        out[idx] = self._mutate_value(fn.inputs[idx]["type"], out[idx], fn.name, fn.inputs[idx].get("name", ""))
        return out

    def fresh_value(self, eth_value: bool, fn: FunctionInfo) -> int:
        if not (eth_value and fn.is_payable):
            return 0
        if self.rng.random() < 0.5:
            return self.rng.choice([0, 1, 10**15, 10**18, 10**20])
        return self.rng.randrange(0, 10**20)

    def fresh_caller(self, default_addrs: list[str]) -> str:
        pool = list(default_addrs) + list(self.attacker_addrs)
        if not pool:
            return _random_address(self.rng)
        return self.rng.choice(pool)

    # ------------------------------------------------------------------

    def _gen(self, sol_type: str, fn_name: str, arg_name: str) -> Any:
        hint = self._hint_for(fn_name, sol_type)
        if hint is not None and self.rng.random() < self.cfg.bias_interesting:
            return hint
        return self._random_for(sol_type)

    def _mutate_value(self, sol_type: str, current: Any, fn_name: str, arg_name: str) -> Any:
        if self.rng.random() < 0.3:
            return self._gen(sol_type, fn_name, arg_name)
        # bit-level mutation for ints
        if sol_type.startswith("uint") or sol_type.startswith("int"):
            try:
                v = int(current)
            except (TypeError, ValueError):
                v = 0
            op = self.rng.choice(["flip", "add", "sub", "neighbor"])
            if op == "flip":
                bits = self._int_bits(sol_type)
                v ^= 1 << self.rng.randrange(min(bits, 256))
            elif op == "add":
                v += self.rng.choice([1, 2, 7, 31, 256, 1024])
            elif op == "sub":
                v -= self.rng.choice([1, 2, 7, 31, 256, 1024])
            else:
                v = self.rng.choice(_INTEREST_UINT)
            return self._clamp_int(sol_type, v)
        return self._random_for(sol_type)

    # ------------------------------------------------------------------

    def _hint_for(self, fn_name: str, sol_type: str) -> Any | None:
        h = self.hints.get(fn_name)
        if not h:
            return None
        if sol_type.startswith("uint"):
            pool = h.values.get("uint", [])
            return self.rng.choice(pool) if pool else None
        if sol_type.startswith("int"):
            pool = h.values.get("int", [])
            return self.rng.choice(pool) if pool else None
        if sol_type == "address":
            pool = h.values.get("address", [])
            return self.rng.choice(pool) if pool else None
        if sol_type == "bool":
            pool = h.values.get("bool", [])
            return self.rng.choice(pool) if pool else None
        if sol_type == "string":
            pool = h.values.get("string", [])
            return self.rng.choice(pool) if pool else None
        if sol_type.startswith("bytes"):
            pool = h.values.get("bytes", [])
            if pool:
                v = self.rng.choice(pool)
                if isinstance(v, str):
                    try:
                        return bytes.fromhex(v[2:] if v.startswith("0x") else v)
                    except ValueError:
                        return v.encode()
                return v
        return None

    def _random_for(self, sol_type: str) -> Any:
        if sol_type.endswith("[]"):
            base = sol_type[:-2]
            length = self.rng.choice([0, 1, 2, 3])
            return [self._random_for(base) for _ in range(length)]
        if "[" in sol_type and sol_type.endswith("]"):
            base, fixed = sol_type.rsplit("[", 1)
            n = int(fixed[:-1])
            return [self._random_for(base) for _ in range(n)]
        if sol_type.startswith("uint"):
            bits = self._int_bits(sol_type)
            if self.rng.random() < self.cfg.bias_interesting:
                v = self.rng.choice(_INTEREST_UINT)
            else:
                v = self.rng.randrange(0, 1 << min(bits, 256))
            return self._clamp_int(sol_type, v)
        if sol_type.startswith("int"):
            bits = self._int_bits(sol_type)
            if self.rng.random() < self.cfg.bias_interesting:
                v = self.rng.choice([-1, 0, 1, 2, -(1 << (bits - 1)), (1 << (bits - 1)) - 1])
            else:
                v = self.rng.randrange(-(1 << (bits - 1)), (1 << (bits - 1)))
            return v
        if sol_type == "address":
            if self.rng.random() < self.cfg.bias_interesting:
                pool = list(_INTEREST_ADDR) + list(self.attacker_addrs)
                if pool:
                    return self.rng.choice(pool)
            return _random_address(self.rng)
        if sol_type == "bool":
            return self.rng.choice([True, False])
        if sol_type == "string":
            n = self.rng.choice([0, 1, 4, 16, 64])
            return "".join(self.rng.choice(string.ascii_letters) for _ in range(n))
        if sol_type == "bytes":
            n = self.rng.choice([0, 1, 4, 32, 64])
            return os.urandom(n)
        if sol_type.startswith("bytes"):
            n = int(sol_type[len("bytes"):]) if len(sol_type) > len("bytes") else 32
            return os.urandom(n)
        if sol_type.startswith("tuple"):
            # We don't fully support tuples; return empty so the encoder errors clearly.
            return ()
        return 0

    @staticmethod
    def _int_bits(sol_type: str) -> int:
        body = sol_type
        if body.startswith("uint"):
            body = body[len("uint"):]
        elif body.startswith("int"):
            body = body[len("int"):]
        try:
            return int(body) if body else 256
        except ValueError:
            return 256

    @classmethod
    def _clamp_int(cls, sol_type: str, v: int) -> int:
        bits = cls._int_bits(sol_type)
        if sol_type.startswith("uint"):
            mask = (1 << bits) - 1
            return v & mask
        signed_max = (1 << (bits - 1)) - 1
        signed_min = -(1 << (bits - 1))
        if v < signed_min:
            v = signed_min
        if v > signed_max:
            v = signed_max
        return v


def _random_address(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))
