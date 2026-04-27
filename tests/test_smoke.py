"""End-to-end smoke tests for EchoFuzz."""

from __future__ import annotations

from pathlib import Path

import pytest

from echofuzz import ContractAnalyzer, EchoFuzzEngine, LLMClient


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "VulnerableBank.sol"


def test_compile_and_extract():
    analyzer = ContractAnalyzer()
    info = analyzer.analyze(EXAMPLE, contract_name="VulnerableBank")
    assert info.name == "VulnerableBank"
    assert info.bytecode
    fuzzable = {f.name for f in info.fuzzable_functions()}
    assert {"deposit", "withdraw", "setAdmin", "withdrawAll", "unsafeTransfer"} <= fuzzable


def test_vfcs_with_mock_llm():
    analyzer = ContractAnalyzer()
    info = analyzer.analyze(EXAMPLE, contract_name="VulnerableBank")
    llm = LLMClient(backend="mock", seed=42)
    engine = EchoFuzzEngine(info, llm=llm, seed=42)
    plan = engine.seed_from_vfcs()
    assert len(plan.sequences) > 0
    # heuristic includes deposit -> withdraw
    chains = [tuple(s.calls) for s in plan.sequences]
    assert any("deposit" in c and "withdraw" in c for c in chains)


def test_short_run_finds_something():
    analyzer = ContractAnalyzer()
    info = analyzer.analyze(EXAMPLE, contract_name="VulnerableBank")
    llm = LLMClient(backend="mock", seed=1)
    engine = EchoFuzzEngine(info, llm=llm, seed=1)
    report = engine.run(iterations=80, feedback_every=40, feedback_max_calls=1)
    assert report.iterations == 80
    assert report.pc_sites > 0
    assert report.corpus_size >= 1
