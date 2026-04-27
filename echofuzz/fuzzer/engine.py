"""EchoFuzz fuzzing engine.

This module implements the iterative fuzzing loop:

  1. Compile the contract and produce a :class:`ContractInfo`.
  2. Use :class:`VFCSGenerator` to seed the corpus with chain-guided
     Vulnerable Function Call Sequences (LLM stage 1).
  3. Run a budgeted fuzzing campaign:
       * sample a test from the corpus
       * mutate either the call sequence or the arguments
       * execute on a forked EVM, collect coverage and bug findings
       * keep tests that increased coverage as new corpus entries
  4. Periodically ask the LLM (stage 2) for new sequences and argument
     hints based on the coverage feedback.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..llm.client import LLMClient
from ..oracles.oracles import BugOracle, DEFAULT_ORACLES, Finding
from ..static_analysis.analyzer import ContractInfo
from ..vfcs.generator import VFCS, ArgumentHint, VFCSGenerator, VFCSPlan
from .corpus import Call, Corpus, TestCase
from .executor import EVMExecutor, ExecutionResult
from .mutator import ABIMutator, MutatorConfig

logger = logging.getLogger(__name__)


@dataclass
class FuzzReport:
    contract: str
    iterations: int
    duration: float
    pc_sites: int
    branch_edges: int
    corpus_size: int
    findings: list[Finding] = field(default_factory=list)
    plan: VFCSPlan | None = None
    coverage_history: list[tuple[int, int]] = field(default_factory=list)  # (iter, pc_sites)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "iterations": self.iterations,
            "duration": self.duration,
            "pc_sites": self.pc_sites,
            "branch_edges": self.branch_edges,
            "corpus_size": self.corpus_size,
            "findings": [
                {
                    "kind": f.kind,
                    "detail": f.detail,
                    "signature": f.signature,
                    "severity": f.severity,
                }
                for f in self.findings
            ],
            "coverage_history": self.coverage_history,
        }


# ---------------------------------------------------------------------------


class EchoFuzzEngine:
    def __init__(
        self,
        contract: ContractInfo,
        llm: LLMClient | None = None,
        oracles: list[BugOracle] | None = None,
        constructor_args: list[Any] | None = None,
        constructor_value: int = 0,
        seed: int | None = None,
        on_event: Callable[[str, dict], None] | None = None,
    ):
        self.contract = contract
        self.llm = llm or LLMClient()
        self.vfcs_gen = VFCSGenerator(self.llm)
        self.oracles = oracles if oracles is not None else list(DEFAULT_ORACLES)
        self.rng = random.Random(seed)
        self.on_event = on_event or (lambda *a, **kw: None)

        self.executor = EVMExecutor(
            contract,
            constructor_args=constructor_args,
            constructor_value=constructor_value,
        )
        self.mutator = ABIMutator(
            functions=contract.fuzzable_functions(),
            attacker_addrs=self.executor.accounts[1:],
            config=MutatorConfig(seed=seed),
        )
        self.corpus = Corpus()
        self.findings_index: dict[str, Finding] = {}
        self.recent_findings: list[Finding] = []
        self.plan: VFCSPlan | None = None

        for o in self.oracles:
            o.setup(self.executor)

    # ------------------------------------------------------------------

    def seed_from_vfcs(self) -> VFCSPlan:
        plan = self.vfcs_gen.generate(self.contract)
        self.plan = plan
        self.mutator.update_hints(plan.hints)
        for vf in plan.sequences:
            tc = self._build_test_from_vfcs(vf)
            if tc.calls:
                self.corpus.add(tc)
        if not self.corpus:
            for fn in self.contract.fuzzable_functions():
                tc = TestCase(
                    calls=[
                        Call(
                            function=fn.name,
                            args=self.mutator.fresh_args(fn),
                            caller=self.mutator.fresh_caller(self.executor.accounts),
                            value=self.mutator.fresh_value(True, fn),
                        )
                    ],
                    energy=1.0,
                    source="random",
                )
                self.corpus.add(tc)
        return plan

    def _build_test_from_vfcs(self, vf: VFCS) -> TestCase:
        calls: list[Call] = []
        fn_map = {f.name: f for f in self.contract.fuzzable_functions()}
        for fn_name in vf.calls:
            fn = fn_map.get(fn_name)
            if fn is None:
                continue
            calls.append(
                Call(
                    function=fn.name,
                    args=self.mutator.fresh_args(fn),
                    caller=self.mutator.fresh_caller(self.executor.accounts),
                    value=self.mutator.fresh_value(True, fn),
                )
            )
        return TestCase(
            calls=calls,
            energy=1.0 + max(0.0, vf.score),
            source="vfcs",
            rationale=vf.rationale,
        )

    # ------------------------------------------------------------------

    def run(
        self,
        iterations: int = 500,
        max_duration: float | None = None,
        feedback_every: int = 100,
        feedback_max_calls: int = 5,
    ) -> FuzzReport:
        start = time.time()
        if self.plan is None:
            self.seed_from_vfcs()

        coverage_history: list[tuple[int, int]] = []
        feedback_calls = 0

        for i in range(iterations):
            if max_duration and time.time() - start > max_duration:
                break

            tc = self._next_test()
            result = self.executor.execute(tc)
            grew = result.new_pc_sites > 0 or result.new_branches > 0
            if grew:
                tc.new_coverage = result.new_pc_sites + result.new_branches
                self.corpus.add(tc)

            for oracle in self.oracles:
                for f in oracle.after_test(self.executor, result):
                    f.test_signature = tc.signature()
                    if f.signature not in self.findings_index:
                        self.findings_index[f.signature] = f
                        self.recent_findings.append(f)
                        self.on_event("finding", {"finding": f, "test": tc})

            if i % 25 == 0:
                coverage_history.append((i, len(self.executor.tracker.pc_sites)))
                self.on_event(
                    "progress",
                    {
                        "iter": i,
                        "pc_sites": len(self.executor.tracker.pc_sites),
                        "branches": len(self.executor.tracker.branch_edges),
                        "corpus": len(self.corpus),
                        "findings": len(self.findings_index),
                    },
                )

            if feedback_every and i and i % feedback_every == 0 and feedback_calls < feedback_max_calls:
                self._invoke_feedback()
                feedback_calls += 1

        coverage_history.append((iterations, len(self.executor.tracker.pc_sites)))

        return FuzzReport(
            contract=self.contract.name,
            iterations=iterations,
            duration=time.time() - start,
            pc_sites=len(self.executor.tracker.pc_sites),
            branch_edges=len(self.executor.tracker.branch_edges),
            corpus_size=len(self.corpus),
            findings=list(self.findings_index.values()),
            plan=self.plan,
            coverage_history=coverage_history,
        )

    # ------------------------------------------------------------------

    def _next_test(self) -> TestCase:
        sample = self.corpus.sample(self.rng)
        if sample is None or self.rng.random() < 0.15:
            return self._random_test()
        return self._mutate_test(sample)

    def _random_test(self) -> TestCase:
        functions = self.contract.fuzzable_functions()
        if not functions:
            return TestCase(calls=[], source="random")
        n = self.rng.choice([1, 1, 2, 2, 3, 4])
        calls = []
        for _ in range(n):
            fn = self.rng.choice(functions)
            calls.append(
                Call(
                    function=fn.name,
                    args=self.mutator.fresh_args(fn),
                    caller=self.mutator.fresh_caller(self.executor.accounts),
                    value=self.mutator.fresh_value(True, fn),
                )
            )
        return TestCase(calls=calls, energy=1.0, source="random")

    def _mutate_test(self, base: TestCase) -> TestCase:
        functions = self.contract.fuzzable_functions()
        fn_map = {f.name: f for f in functions}
        new_calls: list[Call] = []
        for c in base.calls:
            fn = fn_map.get(c.function)
            if fn is None:
                continue
            args = list(c.args)
            if self.rng.random() < 0.7:
                args = self.mutator.mutate_args(fn, args)
            caller = c.caller
            if self.rng.random() < 0.2:
                caller = self.mutator.fresh_caller(self.executor.accounts)
            value = c.value
            if fn.is_payable and self.rng.random() < 0.3:
                value = self.mutator.fresh_value(True, fn)
            new_calls.append(Call(function=fn.name, args=args, caller=caller, value=value))

        # Sequence-level mutations.
        op = self.rng.random()
        if op < 0.15 and functions:
            fn = self.rng.choice(functions)
            new_calls.append(
                Call(
                    function=fn.name,
                    args=self.mutator.fresh_args(fn),
                    caller=self.mutator.fresh_caller(self.executor.accounts),
                    value=self.mutator.fresh_value(True, fn),
                )
            )
        elif op < 0.25 and len(new_calls) > 1:
            i = self.rng.randrange(len(new_calls))
            j = self.rng.randrange(len(new_calls))
            new_calls[i], new_calls[j] = new_calls[j], new_calls[i]
        elif op < 0.32 and len(new_calls) > 1:
            del new_calls[self.rng.randrange(len(new_calls))]

        return TestCase(calls=new_calls, energy=1.0, source="mutated")

    # ------------------------------------------------------------------

    def _invoke_feedback(self) -> None:
        coverage_summary = (
            f"PC sites: {len(self.executor.tracker.pc_sites)}, "
            f"branches: {len(self.executor.tracker.branch_edges)}, "
            f"corpus: {len(self.corpus)}"
        )
        # Build a small list of "uncovered" branch hints: PCs we have NOT
        # taken on JUMPI, which we approximate by looking for JUMPI sites
        # that have only one observed post-PC.
        jumpi_post: dict[tuple[bytes, int], set[int]] = {}
        for addr, pc, post in self.executor.tracker.branch_edges:
            jumpi_post.setdefault((addr, pc), set()).add(post)
        uncovered = [
            {"pc": pc, "op": "JUMPI", "fn": "?"}
            for (addr, pc), post in jumpi_post.items()
            if len(post) == 1
        ][:30]

        seqs, hints = self.vfcs_gen.feedback(
            self.contract,
            coverage_summary,
            uncovered,
            [
                {"kind": f.kind, "detail": f.detail}
                for f in self.recent_findings[-10:]
            ],
        )
        self.recent_findings.clear()
        if hints:
            self.mutator.update_hints(hints)
        for vf in seqs:
            tc = self._build_test_from_vfcs(vf)
            if tc.calls:
                tc.source = "feedback"
                self.corpus.add(tc)
        self.on_event(
            "feedback",
            {"new_sequences": len(seqs), "new_hints": len(hints)},
        )
