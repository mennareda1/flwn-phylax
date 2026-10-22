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
    python -m tests.live_decision1    # ONE real call to your Decision-1 deployment (needs the env vars in its header)

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

Built and tested: core, ports, Bandit, secrets-check, LLM-detector and Decision-1 classifier adapters, Foundry adapter (against a fake
client only), benchmark and bake-off, the contract, and the contract check.

Not built yet: the HTTP layer (FastAPI, auth, job store, idempotency, retention), the fix and
verification services, the security question set and code chunking for the classifier, the classifier promotion test, the Astra corrector adapter, C++, C# and JS lanes.

## Decisions recorded here

- A source file that was not scanned (unsupported language, too large, corrupt) turns a would-be
  PASS into REVIEW_REQUIRED. Docs and config files are listed but do not block a pass.
- A decision of SCAN_FAILED is reserved for engine failures; Flwn treats it like REVIEW_REQUIRED
  (never a pass, human review required).
- `context` hints are accepted but ignored for now; reserved so adding them is not a contract change.
- Webhooks are deferred. Callers poll, with `Prefer: wait=N` to avoid polling when work is quick.
- The decision model is Microsoft-Decision-1 (in Foundry), replacing Jev. Results are traced to the
  exact model version chosen at deployment time (reported as `Microsoft-Decision-1@1`), never to an
  alias. The classifier port is unchanged: only its adapter differs from any other provider.
- The Decision-1 adapter masks secrets itself before anything is sent, retries only transient errors
  (408, 429, 5xx, network) up to 3 times, and never puts the code or a credential in an error. It has
  only been tested against a scripted network: the first real reply must be checked with
  `python -m tests.live_decision1`, because the reply format is taken from third-party descriptions of
  the "System One" format, not from Microsoft's page. Parsing is tolerant about field names but strict
  about meaning: out-of-range probabilities and options that were not offered are errors.
- Classifier failures are ClassifierError subclasses (unavailable, rejected, too large). The scan service
  will treat any of them as a failed engine, so a scan can fail closed but never silently pass.
- A secret found by pattern asks for human review but never blocks on its own: a pattern cannot tell
  a live key from the documented example key, and only HIGH confidence blocks. Masking is liberal
  (a missed secret leaks); reporting is careful (every report is an alarm).
- The secrets check runs on Python only, so a file in another language is never counted as scanned
  because of secrets coverage alone. Widen it together with each language's rules engine.
- When two rule engines agree on one issue they appear as one corroborated finding. A model can join
  a rule's finding only if it claims no more than the rule does, and it never raises the rule's
  severity or confidence; a model that claims more stands alone as a model suspicion.
