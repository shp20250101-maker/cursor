# EchoFuzz

A Python implementation of **EchoFuzz: Empowering Smart Contract Fuzzing
with Large Language Models** (Li et al., ICSE 2026).

EchoFuzz is an LLM-guided greybox fuzzer for Ethereum smart contracts. It
attacks two long-standing weaknesses of pure rule-based contract
fuzzers:

1. The logical gap between random call sequences and the *state
   transitions* that actually expose bugs.
2. The combinatorial explosion of redundant call orderings.

To address both, the paper introduces **Vulnerable Function Call
Sequences (VFCS)**: minimal, behavior-preserving call sequences that
exercise the essential state transitions a bug requires. The framework
has two stages:

```
  ┌────────────────────────────┐      ┌────────────────────────────┐
  │ Stage 1: chain-guided LLM  │      │ Stage 2: iterative fuzzing │
  │  (auditor workflow)        │ ───▶ │  with LLM feedback         │
  │                            │      │                            │
  │  summarize → classify →    │      │  corpus + ABI mutator +    │
  │  propose VFCS + arg hints  │      │  EVM coverage tracker +    │
  └────────────────────────────┘      │  bug oracles               │
                                      └────────────────────────────┘
```

This repo is a faithful reproduction of that architecture. There is no
public source release of the original tool yet, so the implementation is
based on the paper's published description.

## What's inside

| Module | Purpose |
| --- | --- |
| [`echofuzz/static_analysis/analyzer.py`](echofuzz/static_analysis/analyzer.py) | Compiles Solidity with `solcx`, extracts ABI, bytecode, AST-derived reads/writes/calls, storage layout. |
| [`echofuzz/llm/prompts.py`](echofuzz/llm/prompts.py) | Chain-of-prompts implementing the auditor workflow: *summarize → classify → propose VFCS → propose argument hints*, plus a *feedback* prompt for stage 2. |
| [`echofuzz/llm/client.py`](echofuzz/llm/client.py) | Pluggable LLM client. Supports **OpenAI** (real API), **mock** (heuristic, deterministic, zero-cost), and **echo** backends. |
| [`echofuzz/vfcs/generator.py`](echofuzz/vfcs/generator.py) | Runs the chain-guided LLM pipeline and parses VFCS / argument hints, with robust JSON salvage and a heuristic fallback. |
| [`echofuzz/fuzzer/coverage.py`](echofuzz/fuzzer/coverage.py) | Patches the running py-evm computation class to record every executed `(code_address, pc, opcode)` site and every JUMPI edge. |
| [`echofuzz/fuzzer/executor.py`](echofuzz/fuzzer/executor.py) | Deploys the contract on `eth_tester` / py-evm, executes a test sequence inside a snapshot, captures balance deltas and per-call traces. |
| [`echofuzz/fuzzer/mutator.py`](echofuzz/fuzzer/mutator.py) | ABI-aware input generator and mutator. Mixes random sampling, "interesting" boundary values, and the LLM's argument hints. |
| [`echofuzz/fuzzer/corpus.py`](echofuzz/fuzzer/corpus.py) | Energy-aware corpus implementing power-scheduling-style sampling. |
| [`echofuzz/fuzzer/engine.py`](echofuzz/fuzzer/engine.py) | The main fuzz loop: corpus seeding from VFCS, mutation, execution, oracle invocation, and periodic LLM-feedback cycles. |
| [`echofuzz/oracles/oracles.py`](echofuzz/oracles/oracles.py) | Bug oracles: assertion / arithmetic / div-by-zero panics, Ether drain, ownership hijack, SELFDESTRUCT reachability, unchecked external CALL. |
| [`examples/VulnerableBank.sol`](examples/VulnerableBank.sol) | Deliberately vulnerable contract used by the demo and tests. |

## Installation

```bash
pip install -r requirements.txt
```

The first run will install the matching Solidity compiler via `py-solc-x`.

## Quick start

Fuzz the bundled example with the offline mock LLM:

```bash
python -m echofuzz examples/VulnerableBank.sol \
    --contract VulnerableBank \
    --backend mock \
    --iterations 400 \
    --seed 7
```

The output shows the chain-guided VFCS that seeded the corpus, the
coverage-growth trace, periodic LLM-feedback rounds, and any findings:

```
[+] Compiled VulnerableBank (3136 bytes)
    fuzzable functions: ['deposit', 'setAdmin', 'unsafeTransfer', 'withdraw', 'withdrawAll']
[+] LLM backend: mock (model=gpt-4o-mini)
[+] Seeded corpus with 9 VFCS
    - ['setAdmin', 'withdrawAll'] (score=0.85)
    - ['deposit', 'withdraw']     (score=0.85)
    - ['setAdmin', 'withdraw']    (score=0.85)
    ...
[+] Fuzzing for up to 400 iterations...
    [!] FINDING possible-ownership-hijack (high): non-deployer ... called setAdmin
    [!] FINDING possible-ether-drain     (high): non-owner ... received 8.4e17 wei net after sending in 0 wei
```

To use a real LLM, set `OPENAI_API_KEY` and select the OpenAI backend:

```bash
export OPENAI_API_KEY=sk-...
python -m echofuzz examples/VulnerableBank.sol \
    --contract VulnerableBank \
    --backend openai \
    --model gpt-4o-mini \
    --iterations 1000 \
    --report report.json
```

## Programmatic API

```python
from echofuzz import ContractAnalyzer, EchoFuzzEngine, LLMClient

contract = ContractAnalyzer().analyze("examples/VulnerableBank.sol",
                                      contract_name="VulnerableBank")

engine = EchoFuzzEngine(
    contract,
    llm=LLMClient(backend="openai", model="gpt-4o-mini"),
    seed=42,
)
plan = engine.seed_from_vfcs()
print("VFCS:", [s.calls for s in plan.sequences])

report = engine.run(iterations=2000, feedback_every=200)
for f in report.findings:
    print(f.severity, f.kind, "-", f.detail)
```

## How the implementation maps to the paper

* **Chain-guided LLM (paper §3.1)** — the three-step prompt chain in
  `echofuzz/llm/prompts.py` (`step1_summarize`, `step2_classify_functions`,
  `step3_vfcs` + `step3_argument_hints`) mirrors the
  *understand → classify → propose* auditor workflow. `VFCSGenerator`
  parses each step's JSON and gracefully falls back to a heuristic
  generator when the LLM output is missing or malformed.

* **VFCS (paper §3.1)** — `step3_vfcs` explicitly asks for *minimal,
  behavior-preserving* call chains and bounds the length and number of
  proposed sequences to "eliminate combinatorial redundancy", and the
  generator deduplicates / sorts sequences by score.

* **Iterative LLM feedback (paper §3.2)** — `EchoFuzzEngine.run` calls
  `_invoke_feedback` every `feedback_every` iterations. The
  feedback prompt (`prompts.feedback_prompt`) summarizes coverage,
  reports under-explored JUMPI edges, and forwards recent findings, so
  the LLM can propose new sequences and argument hints that target
  unexplored branches. New suggestions are merged into the corpus and
  the mutator's hint table.

* **Branch coverage and energy** — `coverage.py` patches the live py-evm
  computation class so every executed opcode and every JUMPI fall-through
  / taken edge is recorded, and the corpus weights tests by energy and
  coverage gain (a power-scheduling-style approximation).

* **Oracles** — beyond Solidity assertion / panic detection
  (`AssertionOracle`), EchoFuzz reports broken access control
  (`OwnershipHijackOracle`), Ether drain by non-owners
  (`EtherDrainOracle`), reachable `SELFDESTRUCT` (`SuicideOracle`), and
  unchecked low-level CALL (`UncheckedCallOracle`).

## Testing

```bash
python -m pytest -q
```

The smoke tests compile the example contract, exercise the chain-guided
VFCS pipeline against the mock LLM, and run a short fuzzing campaign
end-to-end without requiring any API credentials.

## Limitations

* This is a research-grade reproduction. The original paper's evaluation
  numbers (29% extra branch coverage, 62% extra vulnerabilities, 37
  zero-days) come from a much larger benchmark, longer campaigns, and
  domain-specific oracles tuned to real-world DeFi projects.
* `eth_tester` + py-evm gives correctness and ease of instrumentation
  but is significantly slower than HEVM/REVM. Plug in a faster executor
  via `EVMExecutor` if you need throughput.
* The static analysis is intentionally lightweight: ABI, AST-level
  reads/writes/calls, and storage layout. Production-grade EchoFuzz
  uses Slither-style analysis to enrich prompts.
