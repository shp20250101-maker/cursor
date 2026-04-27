"""Prompts implementing EchoFuzz's chain-guided LLM auditor workflow.

The paper describes a chain of prompts that mirrors how a human auditor
reasons about a contract: first understand the high-level purpose, then
identify state-changing functions, then propose minimal call sequences
that, if combined with carefully chosen arguments, expose vulnerabilities
through essential state transitions (Vulnerable Function Call Sequences,
or VFCS).

Each prompt asks the model to return STRICT JSON so we can parse the
output deterministically.
"""

from __future__ import annotations

from typing import Any

SYSTEM_AUDITOR = (
    "You are an expert smart contract security auditor. "
    "You analyze Solidity contracts and reason about state transitions, "
    "access control, arithmetic, reentrancy, and economic invariants. "
    "When the user asks for structured output, respond with STRICT JSON only "
    "with no prose, no markdown fences."
)


# ---------------------------------------------------------------------------
# Stage 1: chain-guided VFCS generation
# ---------------------------------------------------------------------------


def step1_summarize(contract_source: str, name: str) -> str:
    """First link in the chain: understand the contract's purpose."""
    return (
        f"Read the following Solidity contract and produce a short JSON summary.\n"
        f"Return: {{\"purpose\": str, \"actors\": [str], \"assets\": [str], "
        f"\"invariants\": [str]}}\n\n"
        f"Contract name: {name}\n"
        f"```solidity\n{contract_source}\n```"
    )


def step2_classify_functions(name: str, functions: list[dict[str, Any]]) -> str:
    """Second link: classify each function by role."""
    lines = [f"- {f['signature']}  (mut={f['mutability']})" for f in functions]
    fblock = "\n".join(lines)
    return (
        f"Contract: {name}\n"
        f"Classify each function as one of: state-init, state-mutator, "
        f"asset-transfer, access-control, view-only, dispatcher.\n"
        f"Return JSON: {{\"functions\": [{{\"signature\": str, \"role\": str, "
        f"\"reads\": [str], \"writes\": [str]}}]}}\n\n"
        f"Functions:\n{fblock}\n"
    )


def step3_vfcs(
    name: str,
    contract_source: str,
    functions: list[dict[str, Any]],
    state_vars: list[dict[str, Any]],
    max_len: int = 4,
    n: int = 12,
) -> str:
    """Final link: generate Vulnerable Function Call Sequences.

    The instruction explicitly asks for *minimal, behavior-preserving* call
    chains that exercise essential state transitions, matching the VFCS
    definition from the EchoFuzz paper.
    """
    flines = [f"- {f['signature']}  (mut={f['mutability']})" for f in functions]
    sv_lines = [f"- {sv.get('label', '?')} : {sv.get('type', '?')}" for sv in state_vars]
    return (
        f"You are generating Vulnerable Function Call Sequences (VFCS) for the "
        f"contract `{name}`. A VFCS is a minimal, behavior-preserving sequence of "
        f"public function calls whose composed state transitions are likely to "
        f"expose a bug (reentrancy, broken access control, arithmetic over/underflow, "
        f"unchecked external call, price/oracle manipulation, locked funds, etc.).\n\n"
        f"Constraints:\n"
        f"  * length <= {max_len}, eliminate combinatorial redundancy\n"
        f"  * include at most {n} sequences\n"
        f"  * each call must reference a function from the list below by name only\n"
        f"  * order matters; do not repeat trivial sequences\n\n"
        f"Return JSON exactly: {{\"sequences\": [{{\"calls\": [str], \"score\": float, "
        f"\"rationale\": str, \"target_bug\": str}}]}}\n\n"
        f"State variables:\n" + ("\n".join(sv_lines) or "- (none)") + "\n\n"
        f"Functions:\n" + "\n".join(flines) + "\n\n"
        f"Source (truncated):\n```solidity\n{contract_source[:6000]}\n```"
    )


def step3_argument_hints(
    name: str,
    functions: list[dict[str, Any]],
) -> str:
    """Companion prompt: ask for argument hints per function."""
    flines = [f"- {f['signature']}  inputs={f['inputs']}" for f in functions]
    return (
        f"For contract `{name}`, propose interesting argument values per function "
        f"(boundaries, magic numbers, attacker-controlled addresses, zero, max, etc.).\n"
        f"Return JSON: {{\"hints\": [{{\"function\": str, \"values\": ["
        f"{{\"name\": str, \"uint\": [int], \"int\": [int], \"address\": [str], "
        f"\"bool\": [bool], \"bytes\": [str], \"string\": [str]}}]}}]}}\n\n"
        f"Functions:\n" + "\n".join(flines)
    )


# ---------------------------------------------------------------------------
# Stage 2: iterative LLM feedback during fuzzing
# ---------------------------------------------------------------------------


def feedback_prompt(
    name: str,
    functions: list[dict[str, Any]],
    coverage_summary: str,
    uncovered_branches: list[dict[str, Any]],
    recent_findings: list[dict[str, Any]],
) -> str:
    """Ask the LLM to propose new sequences/hints that target unexplored branches.

    EchoFuzz's iterative stage feeds real-time coverage feedback to the LLM
    to "adaptively promote exploration" toward unexplored branches.
    """
    flines = [f"- {f['signature']}  (mut={f['mutability']})" for f in functions]
    branches = "\n".join(
        f"  * pc={b.get('pc')} op={b.get('op')} fn={b.get('fn', '?')}"
        for b in uncovered_branches[:30]
    ) or "  (none reported)"
    findings = "\n".join(
        f"  * {f.get('kind')}: {f.get('detail', '')[:200]}"
        for f in recent_findings[:10]
    ) or "  (none yet)"
    return (
        f"Contract: {name}\n"
        f"You are co-fuzzing this contract with a greybox fuzzer. Use the runtime "
        f"feedback below to propose new call sequences and argument hints that target "
        f"the unexplored branches. Be concrete; prefer short sequences (2-4 calls).\n\n"
        f"Coverage summary:\n{coverage_summary}\n\n"
        f"Unexplored branches:\n{branches}\n\n"
        f"Recent findings:\n{findings}\n\n"
        f"Return JSON: {{\"sequences\": [{{\"calls\": [str], \"score\": float, "
        f"\"rationale\": str}}], \"hints\": [{{\"function\": str, \"values\": [...]}}], "
        f"\"rationale\": str}}\n\n"
        f"Functions:\n" + "\n".join(flines)
    )
