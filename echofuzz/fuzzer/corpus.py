"""Corpus and test-case data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Call:
    function: str
    args: list[Any]
    caller: str
    value: int = 0


@dataclass
class TestCase:
    calls: list[Call]
    energy: float = 1.0
    new_coverage: int = 0
    source: str = "random"  # random / vfcs / mutated / feedback
    rationale: str = ""

    def signature(self) -> str:
        return " | ".join(f"{c.caller[:6]}:{c.function}({len(c.args)},val={c.value})" for c in self.calls)


class Corpus:
    """Energy-aware priority queue of test cases.

    Higher energy => sampled more often. We approximate the power-scheduling
    used in EchoFuzz / LLM4Fuzz by sampling weighted by energy and recency.
    """

    def __init__(self):
        self._tests: list[TestCase] = []

    def __len__(self) -> int:
        return len(self._tests)

    def add(self, tc: TestCase) -> None:
        self._tests.append(tc)

    def all(self) -> list[TestCase]:
        return list(self._tests)

    def sample(self, rng) -> TestCase | None:
        if not self._tests:
            return None
        weights = [max(0.01, t.energy) for t in self._tests]
        return rng.choices(self._tests, weights=weights, k=1)[0]

    def boost(self, tc: TestCase, factor: float) -> None:
        tc.energy *= factor
