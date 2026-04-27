"""Thin LLM client.

We keep the client minimal so EchoFuzz works in three modes:

  * ``backend="openai"`` - real OpenAI Chat Completions API.
  * ``backend="mock"``   - deterministic, zero-cost backend that returns a
    rule-based response. Useful for tests, CI, and offline development.
  * ``backend="echo"``   - returns the prompt back. Useful for debugging.

The fuzzer never depends on the live API: when no API key is configured,
or ``backend="mock"`` is selected, the pipeline still runs end-to-end with
heuristics in place of the LLM.
"""

from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class LLMResponse:
    text: str
    raw: Any = None


class LLMClient:
    def __init__(
        self,
        backend: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.4,
        max_tokens: int = 1500,
        seed: int | None = None,
    ):
        if backend is None:
            backend = "openai" if os.environ.get("OPENAI_API_KEY") else "mock"
        self.backend = backend
        self.model = model or os.environ.get("ECHOFUZZ_LLM_MODEL", "gpt-4o-mini")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._rng = random.Random(seed)
        self._client = None

        if backend == "openai":
            try:
                from openai import OpenAI

                self._client = OpenAI(api_key=self.api_key)
            except Exception as exc:  # pragma: no cover - fall back if SDK missing
                raise RuntimeError(
                    "openai backend requested but openai SDK is not available"
                ) from exc

    # ------------------------------------------------------------------

    def chat(self, system: str, user: str) -> LLMResponse:
        if self.backend == "openai":
            return self._chat_openai(system, user)
        if self.backend == "echo":
            return LLMResponse(text=f"SYSTEM:\n{system}\n\nUSER:\n{user}")
        return LLMResponse(text=self._mock_response(system, user))

    # ------------------------------------------------------------------

    def _chat_openai(self, system: str, user: str) -> LLMResponse:
        assert self._client is not None
        resp = self._client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = resp.choices[0].message.content or ""
        return LLMResponse(text=text, raw=resp)

    # ------------------------------------------------------------------
    # Mock backend
    # ------------------------------------------------------------------

    def _mock_response(self, system: str, user: str) -> str:
        """Return a JSON object that satisfies the prompts in ``prompts.py``.

        The mock applies simple heuristics so the rest of the pipeline can
        operate without any API credentials.
        """
        functions = self._extract_functions_from_prompt(user)

        if "VFCS" in user or "vulnerable function call sequence" in user.lower():
            return json.dumps({"sequences": _heuristic_sequences(functions)})
        if "argument hints" in user.lower() or "argument suggestion" in user.lower():
            return json.dumps({"hints": _heuristic_hints(functions)})
        if "unexplored" in user.lower() or "feedback" in user.lower():
            return json.dumps(
                {
                    "sequences": _heuristic_sequences(functions, mutate=True),
                    "hints": _heuristic_hints(functions),
                    "rationale": "feedback-based suggestions",
                }
            )
        return json.dumps({"sequences": _heuristic_sequences(functions)})

    @staticmethod
    def _extract_functions_from_prompt(prompt: str) -> list[str]:
        # The prompts always include a "Functions:" block with one signature per line.
        m = re.search(r"Functions:\s*\n((?:- .+\n?)+)", prompt)
        if not m:
            return []
        return [line[2:].strip() for line in m.group(1).strip().splitlines()]


def _heuristic_sequences(functions: list[str], mutate: bool = False) -> list[dict]:
    if not functions:
        return []
    names = [f.split("(")[0] for f in functions]
    seqs: list[dict] = []
    # 1. each function alone
    for n in names:
        seqs.append({"calls": [n], "score": 0.4, "rationale": "single-call baseline"})
    # 2. priority pairs: setter -> getter / withdraw, deposit -> withdraw, etc.
    interesting = [
        ("deposit", "withdraw"),
        ("approve", "transferFrom"),
        ("mint", "burn"),
        ("setOwner", "withdraw"),
        ("setAdmin", "withdrawAll"),
        ("setAdmin", "withdraw"),
        ("init", "withdraw"),
        ("transferOwnership", "withdraw"),
    ]
    for a, b in interesting:
        ca = next((n for n in names if a.lower() in n.lower()), None)
        cb = next((n for n in names if b.lower() in n.lower()), None)
        if ca and cb and ca != cb:
            seqs.append({"calls": [ca, cb], "score": 0.85, "rationale": f"{a}->{b}"})
    # 3. pairs that mutate state then call something else
    if len(names) >= 2:
        seqs.append({"calls": names[:2], "score": 0.55, "rationale": "first two"})
    if mutate and len(names) >= 3:
        seqs.append({"calls": names[:3][::-1], "score": 0.6, "rationale": "reversed"})
    return seqs


def _heuristic_hints(functions: list[str]) -> list[dict]:
    out: list[dict] = []
    for f in functions:
        name = f.split("(")[0]
        out.append(
            {
                "function": name,
                "values": [
                    {"name": "boundary", "uint": [0, 1, 2**256 - 1]},
                    {"name": "small", "uint": [10, 100, 1000]},
                ],
            }
        )
    return out
