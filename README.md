# Flwn security service

An independent service that scans generated code for vulnerabilities, proposes fixes, and
verifies them. It never imports Flwn code and never reads Flwn data. The contract with Flwn is
`openapi.yaml`; everything else can change behind it.

## Run the checks

From this folder (not from inside a subfolder):

    pip install -r requirements.txt
    python -m tests.run_all           # every self-check, one line each
    python -m tests.check_contract    # code vs contract, using real Bandit output
    python -m benchmark.run_benchmark # the 41-case Python scoreboard (static rules only)
    python -m benchmark.bakeoff       # self-test of the model comparison harness

There is no package install step: run everything with `python -m ...` from the repo root.

## Layout

    openapi.yaml                       the contract with Flwn (source of truth)
    security_service/
      version.py                       contract, service and policy versions
      core/                            stable: schema, decision policy, files, scan service, errors, redaction, patching
      ports/                           stable interfaces: analyzer, llm, classifier, corrector
      adapters/                        swappable: bandit, llm_detector, foundry_llm, llm_clients, fakes
    benchmark/                         labeled cases, scoreboard, model bake-off
    tests/                             run_all.py, check_contract.py

Rule of thumb: `core/` and `ports/` never change when a provider changes. Only `adapters/` and
`config` do. A new provider must pass the port's validation rules and clear the benchmark gate.

## Status

Built and tested: core, ports, Bandit and LLM-detector adapters, Foundry adapter (against a fake
client only), benchmark and bake-off, the contract, and the contract check.

Not built yet: the HTTP layer (FastAPI, auth, job store, idempotency, retention), the fix and
verification services, the Jev classifier adapter, the Astra corrector adapter, C++, C# and JS lanes.

## Decisions recorded here

- A source file that was not scanned (unsupported language, too large, corrupt) turns a would-be
  PASS into REVIEW_REQUIRED. Docs and config files are listed but do not block a pass.
- A decision of SCAN_FAILED is reserved for engine failures; Flwn treats it like REVIEW_REQUIRED
  (never a pass, human review required).
- `context` hints are accepted but ignored for now; reserved so adding them is not a contract change.
- Webhooks are deferred. Callers poll, with `Prefer: wait=N` to avoid polling when work is quick.
- Jev model ids are pinned (for example `jev-1.13.0`), never aliases, and the exact version that
  answered is recorded in every result.
