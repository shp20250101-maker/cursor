"""EchoFuzz: LLM-guided smart contract fuzzer.

A faithful reproduction of the architecture described in
"EchoFuzz: Empowering Smart Contract Fuzzing with Large Language Models"
(Li et al., ICSE 2026).

The framework has two stages:

1. Chain-guided LLM generation of Vulnerable Function Call Sequences (VFCS):
   the LLM mimics an expert auditor and emits minimal, behavior-preserving
   call sequences that are likely to expose bugs through essential state
   transitions.

2. Iterative fuzzing where an LLM consumes real-time coverage / branch
   feedback and proposes new sequences and argument hints to steer the
   fuzzer toward unexplored branches.
"""

from .static_analysis.analyzer import ContractAnalyzer
from .vfcs.generator import VFCSGenerator
from .fuzzer.engine import EchoFuzzEngine
from .llm.client import LLMClient

__all__ = [
    "ContractAnalyzer",
    "VFCSGenerator",
    "EchoFuzzEngine",
    "LLMClient",
]

__version__ = "0.1.0"
