"""Static analysis of Solidity contracts.

We compile the contract with solcx to extract:
  - ABI (entry points, types, payable / state-mutability)
  - bytecode + deployed bytecode (for deployment & coverage instrumentation)
  - source map / opcode list (for branch / instruction coverage)
  - state variables (from compiler storage layout)
  - a function call graph approximation (which functions reference which
    state variables, and which functions call other public functions)

The static facts produced here feed the chain-guided LLM prompts and the
fuzzing engine's coverage tracker.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import solcx


@dataclass
class FunctionInfo:
    name: str
    selector: str  # 4-byte hex selector (no 0x), "" for fallback/receive/constructor
    signature: str  # canonical signature, e.g. "transfer(address,uint256)"
    inputs: list[dict[str, Any]] = field(default_factory=list)
    outputs: list[dict[str, Any]] = field(default_factory=list)
    state_mutability: str = "nonpayable"  # pure / view / nonpayable / payable
    kind: str = "function"  # function / constructor / fallback / receive
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)  # other internal/public functions
    source: str = ""  # function source body

    @property
    def is_payable(self) -> bool:
        return self.state_mutability == "payable"

    @property
    def is_view(self) -> bool:
        return self.state_mutability in ("view", "pure")


@dataclass
class ContractInfo:
    name: str
    abi: list[dict[str, Any]]
    bytecode: str
    deployed_bytecode: str
    source: str
    functions: list[FunctionInfo]
    state_variables: list[dict[str, Any]] = field(default_factory=list)
    solc_version: str = ""

    def fuzzable_functions(self) -> list[FunctionInfo]:
        """Return functions the fuzzer can call (skip view/pure & constructor)."""
        out = []
        for f in self.functions:
            if f.kind == "constructor":
                continue
            if f.is_view:
                continue
            if not f.selector and f.kind == "function":
                continue
            out.append(f)
        return out

    def function_by_selector(self, selector: str) -> FunctionInfo | None:
        selector = selector.lower().lstrip("0x")
        for f in self.functions:
            if f.selector.lower() == selector:
                return f
        return None


# ---------------------------------------------------------------------------


class ContractAnalyzer:
    """Compile a Solidity source file and extract structured information."""

    def __init__(self, solc_version: str = "0.8.20"):
        self.solc_version = solc_version
        try:
            solcx.install_solc(solc_version)
        except Exception:
            pass
        solcx.set_solc_version(solc_version)

    def analyze(self, source_path: str | Path, contract_name: str | None = None) -> ContractInfo:
        source_path = Path(source_path)
        source = source_path.read_text()
        return self.analyze_source(source, contract_name=contract_name, file_name=source_path.name)

    def analyze_source(
        self,
        source: str,
        contract_name: str | None = None,
        file_name: str = "Contract.sol",
    ) -> ContractInfo:
        compiled = solcx.compile_standard(
            {
                "language": "Solidity",
                "sources": {file_name: {"content": source}},
                "settings": {
                    "outputSelection": {
                        "*": {
                            "*": [
                                "abi",
                                "evm.bytecode.object",
                                "evm.deployedBytecode.object",
                                "evm.methodIdentifiers",
                                "evm.deployedBytecode.sourceMap",
                                "storageLayout",
                            ],
                            "": ["ast"],
                        }
                    },
                    "optimizer": {"enabled": False},
                },
            },
            solc_version=self.solc_version,
        )

        contracts = compiled["contracts"][file_name]
        if contract_name is None:
            contract_name = next(iter(contracts.keys()))
        if contract_name not in contracts:
            raise ValueError(
                f"Contract {contract_name!r} not found in {file_name}. "
                f"Available: {list(contracts.keys())}"
            )

        c = contracts[contract_name]
        abi = c["abi"]
        bytecode = c["evm"]["bytecode"]["object"]
        deployed = c["evm"]["deployedBytecode"]["object"]
        method_ids = c["evm"].get("methodIdentifiers", {})
        storage_layout = c.get("storageLayout") or {}
        ast = compiled["sources"][file_name].get("ast", {})

        functions = self._build_functions(abi, method_ids, ast, contract_name, source)
        # Drop the placeholder; source is now sliced inline.
        state_vars = list(storage_layout.get("storage", []))

        return ContractInfo(
            name=contract_name,
            abi=abi,
            bytecode=bytecode,
            deployed_bytecode=deployed,
            source=source,
            functions=functions,
            state_variables=state_vars,
            solc_version=self.solc_version,
        )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _build_functions(
        self,
        abi: list[dict[str, Any]],
        method_ids: dict[str, str],
        ast: dict,
        contract_name: str,
        source: str,
    ) -> list[FunctionInfo]:
        functions: list[FunctionInfo] = []

        self._last_source = source
        ast_funcs = self._collect_ast_functions(ast, contract_name)

        for entry in abi:
            kind = entry.get("type", "function")
            if kind not in ("function", "constructor", "fallback", "receive"):
                continue
            name = entry.get("name", kind)
            inputs = entry.get("inputs", [])
            outputs = entry.get("outputs", [])
            mut = entry.get("stateMutability", "nonpayable")

            if kind == "function":
                sig = self._signature(name, inputs)
                selector = method_ids.get(sig, "")
            else:
                sig = kind
                selector = ""

            ast_info = ast_funcs.get(sig) or ast_funcs.get(name) or {}

            functions.append(
                FunctionInfo(
                    name=name,
                    selector=selector,
                    signature=sig,
                    inputs=inputs,
                    outputs=outputs,
                    state_mutability=mut,
                    kind=kind,
                    reads=ast_info.get("reads", []),
                    writes=ast_info.get("writes", []),
                    calls=ast_info.get("calls", []),
                    source=ast_info.get("source", ""),
                )
            )
        return functions

    @staticmethod
    def _signature(name: str, inputs: list[dict[str, Any]]) -> str:
        def t(i: dict[str, Any]) -> str:
            base = i["type"]
            if base.startswith("tuple"):
                comps = ",".join(t(c) for c in i.get("components", []))
                # preserve array suffix on the tuple, e.g. tuple[]
                suffix = base[len("tuple"):]
                return f"({comps}){suffix}"
            return base
        return f"{name}({','.join(t(i) for i in inputs)})"

    def _collect_ast_functions(self, ast: dict, contract_name: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        if not ast:
            return out
        for node in ast.get("nodes", []):
            if node.get("nodeType") != "ContractDefinition":
                continue
            if node.get("name") != contract_name:
                continue
            for sub in node.get("nodes", []):
                if sub.get("nodeType") != "FunctionDefinition":
                    continue
                fname = sub.get("name") or sub.get("kind", "")
                params = sub.get("parameters", {}).get("parameters", [])
                in_types = [p.get("typeDescriptions", {}).get("typeString", "") for p in params]
                # Build a coarse canonical signature for matching.
                sig = f"{fname}({','.join(in_types)})"
                reads, writes, calls = _walk_refs(sub)
                src = _slice_source(sub, self._last_source)
                out[sig] = {
                    "reads": sorted(set(reads)),
                    "writes": sorted(set(writes)),
                    "calls": sorted(set(calls)),
                    "source": src,
                }
                out.setdefault(fname, out[sig])
        return out


def _walk_refs(node: Any) -> tuple[list[str], list[str], list[str]]:
    reads: list[str] = []
    writes: list[str] = []
    calls: list[str] = []

    def visit(n: Any, lhs: bool = False) -> None:
        if isinstance(n, dict):
            nt = n.get("nodeType")
            if nt == "Assignment":
                visit(n.get("leftHandSide"), lhs=True)
                visit(n.get("rightHandSide"), lhs=False)
                return
            if nt == "FunctionCall":
                expr = n.get("expression", {})
                ename = expr.get("name") or expr.get("memberName")
                if ename:
                    calls.append(ename)
                visit(expr, lhs=False)
                for a in n.get("arguments", []) or []:
                    visit(a, lhs=False)
                return
            if nt == "Identifier":
                refs = n.get("referencedDeclaration")
                name = n.get("name")
                # State var refs have a contract-level declaration; we collect
                # all bare identifiers and leave ranking to the LLM.
                if name:
                    if lhs:
                        writes.append(name)
                    else:
                        reads.append(name)
                return
            for v in n.values():
                visit(v, lhs=False)
        elif isinstance(n, list):
            for item in n:
                visit(item, lhs=False)

    visit(node)
    return reads, writes, calls


def _slice_source(fn_node: dict, full_source: str) -> str:
    src = fn_node.get("src", "")
    m = re.match(r"(\d+):(\d+):", src)
    if not m:
        return ""
    start = int(m.group(1))
    length = int(m.group(2))
    return full_source[start : start + length]
