"""Vulnerable Function Call Sequence (VFCS) generation.

Implements EchoFuzz's chain-guided LLM workflow:

    summarize -> classify -> propose VFCS (+ argument hints)

The generator is robust: when the LLM produces malformed output we fall
back to a heuristic generator so the fuzzer always has seeds to work with.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from ..llm.client import LLMClient
from ..llm import prompts
from ..static_analysis.analyzer import ContractInfo, FunctionInfo

logger = logging.getLogger(__name__)


@dataclass
class VFCS:
    calls: list[str]  # function names, in order
    score: float = 0.5
    rationale: str = ""
    target_bug: str = ""


@dataclass
class ArgumentHint:
    function: str
    values: dict[str, list[Any]] = field(default_factory=dict)


@dataclass
class VFCSPlan:
    summary: dict[str, Any]
    classifications: list[dict[str, Any]]
    sequences: list[VFCS]
    hints: list[ArgumentHint]


class VFCSGenerator:
    def __init__(self, llm: LLMClient | None = None, max_len: int = 4, n: int = 12):
        self.llm = llm or LLMClient()
        self.max_len = max_len
        self.n = n

    # ------------------------------------------------------------------

    def generate(self, contract: ContractInfo) -> VFCSPlan:
        fuzzable = contract.fuzzable_functions()
        func_dicts = [
            {
                "signature": f.signature,
                "mutability": f.state_mutability,
                "inputs": [{"name": i.get("name", ""), "type": i["type"]} for i in f.inputs],
                "kind": f.kind,
            }
            for f in fuzzable
        ]

        # Chain step 1: summarize
        summary = self._safe_json(
            self.llm.chat(
                prompts.SYSTEM_AUDITOR,
                prompts.step1_summarize(contract.source, contract.name),
            ).text,
            default={"purpose": "", "actors": [], "assets": [], "invariants": []},
        )

        # Chain step 2: classify
        classified = self._safe_json(
            self.llm.chat(
                prompts.SYSTEM_AUDITOR,
                prompts.step2_classify_functions(contract.name, func_dicts),
            ).text,
            default={"functions": []},
        ).get("functions", [])

        # Chain step 3a: VFCS
        raw_vfcs = self._safe_json(
            self.llm.chat(
                prompts.SYSTEM_AUDITOR,
                prompts.step3_vfcs(
                    contract.name,
                    contract.source,
                    func_dicts,
                    contract.state_variables,
                    max_len=self.max_len,
                    n=self.n,
                ),
            ).text,
            default={"sequences": []},
        )
        sequences = self._parse_sequences(raw_vfcs.get("sequences", []), fuzzable)

        # Chain step 3b: argument hints
        raw_hints = self._safe_json(
            self.llm.chat(
                prompts.SYSTEM_AUDITOR,
                prompts.step3_argument_hints(contract.name, func_dicts),
            ).text,
            default={"hints": []},
        )
        hints = self._parse_hints(raw_hints.get("hints", []), fuzzable)

        # Always include a fallback baseline.
        if not sequences:
            sequences = self._heuristic_sequences(fuzzable)

        sequences = self._dedupe_minimal(sequences)
        return VFCSPlan(
            summary=summary,
            classifications=classified,
            sequences=sequences,
            hints=hints,
        )

    # ------------------------------------------------------------------

    def feedback(
        self,
        contract: ContractInfo,
        coverage_summary: str,
        uncovered: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> tuple[list[VFCS], list[ArgumentHint]]:
        fuzzable = contract.fuzzable_functions()
        func_dicts = [
            {"signature": f.signature, "mutability": f.state_mutability, "inputs": f.inputs}
            for f in fuzzable
        ]
        raw = self._safe_json(
            self.llm.chat(
                prompts.SYSTEM_AUDITOR,
                prompts.feedback_prompt(
                    contract.name,
                    func_dicts,
                    coverage_summary,
                    uncovered,
                    findings,
                ),
            ).text,
            default={"sequences": [], "hints": []},
        )
        seqs = self._parse_sequences(raw.get("sequences", []), fuzzable)
        hints = self._parse_hints(raw.get("hints", []), fuzzable)
        return seqs, hints

    # ------------------------------------------------------------------

    @staticmethod
    def _safe_json(text: str, default: dict[str, Any]) -> dict[str, Any]:
        if not text:
            return default
        # Strip markdown fences if any.
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Best-effort: extract the largest JSON object substring.
            m = re.search(r"\{.*\}", cleaned, flags=re.S)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass
        logger.debug("LLM returned non-JSON; using default.\n%s", text[:300])
        return default

    @staticmethod
    def _parse_sequences(
        raw: list[Any], functions: list[FunctionInfo]
    ) -> list[VFCS]:
        names = {f.name for f in functions}
        out: list[VFCS] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            calls = [c for c in item.get("calls", []) if isinstance(c, str)]
            calls = [c for c in calls if c in names]
            if not calls:
                continue
            out.append(
                VFCS(
                    calls=calls,
                    score=float(item.get("score", 0.5) or 0.5),
                    rationale=str(item.get("rationale", ""))[:300],
                    target_bug=str(item.get("target_bug", ""))[:80],
                )
            )
        return out

    @staticmethod
    def _parse_hints(raw: list[Any], functions: list[FunctionInfo]) -> list[ArgumentHint]:
        names = {f.name for f in functions}
        out: list[ArgumentHint] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            fn = item.get("function")
            if fn not in names:
                continue
            values: dict[str, list[Any]] = {"uint": [], "int": [], "address": [], "bool": [], "bytes": [], "string": []}
            for v in item.get("values", []) or []:
                if not isinstance(v, dict):
                    continue
                for key in values:
                    vals = v.get(key)
                    if isinstance(vals, list):
                        values[key].extend(vals)
            out.append(ArgumentHint(function=fn, values=values))
        return out

    @staticmethod
    def _heuristic_sequences(functions: list[FunctionInfo]) -> list[VFCS]:
        names = [f.name for f in functions]
        seqs = [VFCS(calls=[n], score=0.4, rationale="single-call baseline") for n in names]
        for a, b in [
            ("deposit", "withdraw"),
            ("approve", "transferFrom"),
            ("mint", "burn"),
            ("setOwner", "withdraw"),
            ("setAdmin", "withdrawAll"),
            ("setAdmin", "withdraw"),
            ("transferOwnership", "withdraw"),
        ]:
            ca = next((n for n in names if a.lower() in n.lower()), None)
            cb = next((n for n in names if b.lower() in n.lower()), None)
            if ca and cb and ca != cb:
                seqs.append(VFCS(calls=[ca, cb], score=0.85, rationale=f"{a}->{b}"))
        return seqs

    @staticmethod
    def _dedupe_minimal(seqs: list[VFCS]) -> list[VFCS]:
        # Drop sequences that are non-minimal supersets of higher-scored ones.
        seen: dict[tuple[str, ...], VFCS] = {}
        for s in sorted(seqs, key=lambda x: -x.score):
            key = tuple(s.calls)
            if key in seen:
                continue
            seen[key] = s
        return list(seen.values())
