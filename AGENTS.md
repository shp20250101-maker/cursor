# AGENTS.md

## Cursor Cloud specific instructions

EchoFuzz is a single, self-contained Python package (`echofuzz/`) implementing an
LLM-guided smart-contract fuzzer. There is no server, database, or GUI — it is a
CLI plus a small programmatic API, so all testing is terminal-driven.

### Environment

- Python dependencies are installed into a virtualenv at `.venv` (gitignored) by
  the startup update script. Activate it with `source .venv/bin/activate`, or call
  binaries directly via `.venv/bin/python` / `.venv/bin/pytest`.
- On the **first** compile/test run, `py-solc-x` downloads the `solc 0.8.20`
  compiler (into `~/.solcx`) over the network. This is cached afterward, so the
  first invocation is slower than later ones and requires network access.

### Common commands (run inside the venv)

- Tests: `python -m pytest -q` — 3 end-to-end smoke tests, no API keys needed.
- Run the fuzzer on the bundled example (offline, deterministic mock LLM):
  `python -m echofuzz examples/VulnerableBank.sol --contract VulnerableBank --backend mock --iterations 400 --seed 7`
- There is no configured linter or CI in this repo.

### Notes

- The default LLM backend is `mock` (heuristic, zero-cost) when `OPENAI_API_KEY`
  is not set; pass `--backend openai` and set `OPENAI_API_KEY` to use the real API.
  No credentials are required for tests or the mock demo.
