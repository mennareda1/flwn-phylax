# Flwn security service

An independent service that scans generated code for vulnerabilities, proposes fixes, and verifies
them. It never imports Flwn code and never reads Flwn data. The contract with Flwn is `openapi.yaml`;
everything else can change behind it.

## Quick start (Windows PowerShell)

Run every command from this folder, the one that contains `security_service` and `tests`.

    pip install -r requirements.txt
    Copy-Item .env.example .env          # then open .env and fill in your values (see the table below)
    python -m security_service.config    # checks your settings, with NO network call
    python -m tests.live_decision1       # ONE real call to your Decision-1 deployment
    python -m tests.run_all              # every automated check, one line each

`.env` holds your endpoint and key. It is git-ignored: never commit it, paste it into a chat, or
screenshot it. `.env.example` is the committed template and contains placeholders only.

## Settings (environment variables, or the same names in `.env`)

| Variable | Needed | Default | Meaning |
|---|---|---|---|
| `FOUNDRY_ENDPOINT` | yes | | Your Foundry resource endpoint. The full `.../providers/microsoft/v1/systemone` URL also works. |
| `FOUNDRY_API_KEY` | yes, unless Entra | | Your API key. |
| `DECISION1_DEPLOYMENT` | yes | `decision-1` | The deployment name you chose in Foundry. Not "Microsoft-Decision-1" unless you kept the portal's default. |
| `DECISION1_MODEL_VERSION` | no | `1` | The model version chosen at deployment. |
| `DECISION1_AUTH` | no | `key` | `key` sends the API key. `entra` signs in with Microsoft Entra ID (`az login`, `pip install azure-identity`). |
| `DECISION1_ENDPOINT`, `DECISION1_API_KEY` | no | the two `FOUNDRY_*` above | A separate endpoint or key for Decision-1 only. |
| `DECISION1_TIMEOUT` | no | `20` | Seconds to wait per attempt. |
| `DECISION1_MAX_ATTEMPTS` | no | `3` | Attempts on temporary errors (429, 5xx, network). |
| `SCAN_MAX_FILES`, `SCAN_MAX_FILE_BYTES`, `SCAN_MAX_TOTAL_BYTES` | no | `50`, `200000`, `1000000` | Request limits. |
| `SECURITY_ENV_FILE` | no | | Path of a `.env` file to use instead of the default lookup. |

How settings are found, in order of priority:

1. Variables set in your terminal (for example `$env:FOUNDRY_API_KEY = "..."`) always win.
2. Then the `.env` file: `SECURITY_ENV_FILE` if set, else `.env` in the current folder, else `.env` in the repo root.
3. Then the defaults above.

A `.env` file is read only by entry points (`tests.live_decision1`, `security_service.config`, and later
the HTTP service). Library code and the automated checks never read it, so a real `.env` cannot change
what a test does.

## If a call fails

`python -m security_service.config` shows what the program sees. The live test then prints the reason:

| Message | Cause | Fix |
|---|---|---|
| `authentication failed (HTTP 401)` | The key is missing, wrong, expired, or from another resource | Copy the key from your deployment's details page |
| `authentication failed (HTTP 403)` | The identity cannot use the deployment | Check its role assignment (Entra) |
| `HTTP 404` | Wrong endpoint, or the deployment name does not exist | Use the resource endpoint, and the exact deployment name |
| `HTTP 422` | The deployment name or a question is not supported | `DECISION1_DEPLOYMENT` must be the deployment name |
| `rate limit` (429) | The deployment's quota is exceeded | Add capacity, or lower the request rate |
| `network error` | No connection, firewall, VPN, or timeout | Check the endpoint host and your network |
| `Cannot start: ...` | A setting is missing or still a placeholder | Edit `.env`, then run the config check again |

## Layout

    openapi.yaml                       the contract with Flwn (source of truth)
    .env.example                       committed template for your settings (the real .env is never committed)
    security_service/
      config.py                        settings from the environment and .env; `python -m security_service.config`
      version.py                       contract, service and policy versions
      core/                            stable: schema, decision policy, files, scan service, errors, redaction, patching
      ports/                           stable interfaces: analyzer, llm, classifier, corrector
      adapters/                        swappable: bandit, secrets_check, llm_detector, decision1, foundry_llm, llm_clients, fakes
    benchmark/                         labeled cases, scoreboard, model bake-off
    tests/                             run_all, check_contract, check_transport, check_layout, live_decision1

Rule of thumb: `core/` and `ports/` never change when a provider changes. Only `adapters/` and
configuration do. A new provider must pass the port's validation rules and clear the benchmark gate.

Other commands: `python -m tests.check_contract` (code against the contract, with real Bandit output),
`python -m benchmark.run_benchmark` (the 50-case Python scoreboard), `python -m benchmark.bakeoff`
(self-test of the model comparison harness).

## Status

Built and tested: the core, the ports, the Bandit, secrets-check, LLM-detector and Decision-1 classifier
adapters, the settings and `.env` support, the benchmark and bake-off, the contract, and an end-to-end
test of the real network code against a fake server on this machine.

Not yet run against a real model: the LLM detector, the Foundry adapter, and Decision-1 itself (its
request side is checked against Microsoft's page; its exact reply keys are not shown there, so the
first real call settles them).

Not built yet: the HTTP service (FastAPI, auth, job store, idempotency, retention), the fix and
verification services, the security question set and code chunking for the classifier, the classifier
promotion test, the Astra corrector adapter, and the C++, C# and JS lanes.

## Decisions recorded here

- A source file that was not scanned (unsupported language, too large, corrupt) turns a would-be PASS
  into REVIEW_REQUIRED. Docs and config files are listed but do not block a pass.
- SCAN_FAILED is reserved for engine failures; Flwn treats it like REVIEW_REQUIRED (never a pass, human
  review required).
- `context` hints are accepted but ignored for now; reserved so adding them is not a contract change.
- Webhooks are deferred. Callers poll, with `Prefer: wait=N` to avoid polling when work is quick.
- The decision model is Microsoft-Decision-1 (in Foundry), replacing Jev. Results are traced to the exact
  model version chosen at deployment time (reported as `Microsoft-Decision-1@1`), never to an alias. The
  classifier port is unchanged: only its adapter differs from any other provider.
- Decision-1 was checked against Microsoft's page "Deploy and use Microsoft-Decision-1 in Microsoft
  Foundry" (updated 2026-10-09): endpoint path, request shape, both auth methods, error causes. Not
  stated there, so still unverified: the reply keys for a yes/no probability and per-option
  probabilities, any input limit, and any rate limit. Microsoft's region table lists the model only as
  Global Standard and Data Zone Standard (no regional type); the US regions show for both, and the
  Europe rows must be checked in the portal before promising EU-only processing.
- The Decision-1 adapter masks secrets itself before anything is sent, retries only temporary errors
  (408, 429, 5xx, network), and never puts the code or a credential in an error. Parsing is tolerant
  about field names but strict about meaning: out-of-range probabilities and options that were not
  offered are errors.
- Classifier failures are ClassifierError subclasses (unavailable, rejected, too large). The scan service
  will treat any of them as a failed engine, so a scan can fail closed but never silently pass.
- Settings come from the environment; a `.env` file is read only by entry points and never by library
  code or tests; real environment variables beat the file; a placeholder or a missing value is reported
  before any call is made.
- The secrets check lives in `secrets_check.py`, not `secrets.py`: a module named `secrets` shadows the
  standard library's whenever its folder is first on the path (for example when a file there is run with
  an editor's Run button), which breaks every `import secrets` in that process.
- A secret found by pattern asks for human review but never blocks on its own: a pattern cannot tell a
  live key from the documented example key, and only HIGH confidence blocks. Masking is liberal (a
  missed secret leaks); reporting is careful (every report is an alarm). The known gap: a real secret
  assigned to an innocently named variable (for example `backup = "..."`) is neither reported nor masked.
- The secrets check runs on Python only, so a file in another language is never counted as scanned
  because of secrets coverage alone. Widen it together with each language's rules engine.
- When two rule engines agree on one issue they appear as one corroborated finding. A model can join a
  rule's finding only if it claims no more than the rule does, and it never raises the rule's severity or
  confidence; a model that claims more stands alone as a model suspicion.
