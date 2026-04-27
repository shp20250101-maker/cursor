"""Command-line interface for EchoFuzz.

Usage:

    python -m echofuzz path/to/Contract.sol \
        --contract MyContract \
        --iterations 1000 \
        --backend mock

Set ``OPENAI_API_KEY`` and ``--backend openai`` to use the real LLM.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import ContractAnalyzer, EchoFuzzEngine, LLMClient


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser("echofuzz")
    p.add_argument("source", help="Path to a Solidity source file.")
    p.add_argument("--contract", help="Contract name (default: first in file).")
    p.add_argument("--solc", default="0.8.20", help="solc version to use.")
    p.add_argument("--iterations", type=int, default=500)
    p.add_argument("--max-duration", type=float, default=None)
    p.add_argument("--feedback-every", type=int, default=100)
    p.add_argument("--feedback-max-calls", type=int, default=5)
    p.add_argument(
        "--backend",
        choices=["openai", "mock", "echo"],
        default=None,
        help="LLM backend (default: openai if OPENAI_API_KEY else mock)",
    )
    p.add_argument("--model", default=None)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--report", default=None, help="Write JSON report to this path.")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)

    logging.basicConfig(
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    analyzer = ContractAnalyzer(solc_version=args.solc)
    contract = analyzer.analyze(args.source, contract_name=args.contract)

    print(f"[+] Compiled {contract.name} ({len(contract.bytecode)//2} bytes)")
    print(f"    fuzzable functions: {[f.name for f in contract.fuzzable_functions()]}")

    llm = LLMClient(backend=args.backend, model=args.model)
    print(f"[+] LLM backend: {llm.backend} (model={llm.model})")

    def on_event(kind: str, payload: dict) -> None:
        if kind == "progress":
            print(
                f"    iter={payload['iter']} pc={payload['pc_sites']} "
                f"branches={payload['branches']} corpus={payload['corpus']} "
                f"findings={payload['findings']}"
            )
        elif kind == "finding":
            f = payload["finding"]
            print(f"    [!] FINDING {f.kind} ({f.severity}): {f.detail}")
        elif kind == "feedback":
            print(
                f"    [llm-feedback] +{payload['new_sequences']} sequences "
                f"+{payload['new_hints']} hints"
            )

    engine = EchoFuzzEngine(
        contract=contract,
        llm=llm,
        seed=args.seed,
        on_event=on_event,
    )
    plan = engine.seed_from_vfcs()
    print(f"[+] Seeded corpus with {len(plan.sequences)} VFCS")
    for s in plan.sequences[:8]:
        print(f"    - {s.calls} (score={s.score:.2f}) {s.target_bug}")

    print(f"[+] Fuzzing for up to {args.iterations} iterations...")
    report = engine.run(
        iterations=args.iterations,
        max_duration=args.max_duration,
        feedback_every=args.feedback_every,
        feedback_max_calls=args.feedback_max_calls,
    )
    print()
    print(f"[=] Done in {report.duration:.1f}s")
    print(f"    iterations={report.iterations}")
    print(f"    pc_sites={report.pc_sites}  branches={report.branch_edges}")
    print(f"    corpus={report.corpus_size}  findings={len(report.findings)}")
    for f in report.findings:
        print(f"    [!] {f.kind} ({f.severity}): {f.detail}")

    if args.report:
        Path(args.report).write_text(json.dumps(report.to_dict(), indent=2))
        print(f"[+] Wrote JSON report to {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
