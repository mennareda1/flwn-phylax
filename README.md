# Flwn security service

An independent service that scans generated code for vulnerabilities, proposes fixes, and verifies
them. It never imports Flwn code and never reads Flwn data. The contract with Flwn is `openapi.yaml`;
everything else can change behind it.

## Quick start (Windows PowerShell)

Run every command from this folder, the one that contains `security_service` and `tests`.

    pip install -r requirements.txt
    python -m security_service.config --init   # ONCE: creates .env from the template (it never overwrites an existing .env)
    notepad .env                               # fill in your values (see the table below), save, close
    python -m security_service.config          # checks your settings, with NO network call
    python -m tests.live_decision1             # ONE real call to your Decision-1 deployment
    python -m tests.run_all                    # every automated check, one line each

Run the `--init` line only once. Every other line can be repeated as often as you like and never changes
your settings. (Do not create `.env` by copying the template over it: a copy overwrites silently, which wipes a
filled-in file. `--init` is the safe way.)

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
| `CLASSIFIER_ENABLED` | no | `false` | `true` also asks Decision-1 about every Python file in a real scan (see below). |
| `CLASSIFIER_REQUIRED` | no | `false` | `true` makes a Decision-1 outage turn a would-be pass into `scan_failed`. |
| `CLASSIFIER_THRESHOLD` | no | `0.70` | Probability at or above which a category becomes a finding. 0.70 is what the held-out test validated. |
| `SERVICE_API_KEYS` | for the service | none | Who may call it: `name:scopes:key`, comma-separated. Make a key with `python -m security_service.api --new-key`. |
| `SERVICE_HOST`, `SERVICE_PORT` | no | `127.0.0.1`, `8080` | Where it listens. `127.0.0.1` means this computer only. |
| `SERVICE_RETENTION_HOURS` | no | `24` | How long submitted code and results are kept (in memory only). |
| `SERVICE_WORKERS`, `SERVICE_RATE_LIMIT_PER_MINUTE`, `SERVICE_MAX_WAIT_SECONDS` | no | `4`, `120`, `30` | Scans at once, requests per minute per caller, longest `Prefer: wait`. |
| `SCAN_MAX_FILES`, `SCAN_MAX_FILE_BYTES`, `SCAN_MAX_TOTAL_BYTES` | no | `50`, `200000`, `1000000` | Request limits. |
| `SECURITY_ENV_FILE` | no | | Path of a `.env` file to use instead of the default lookup. |

How settings are found, in order of priority:

1. Variables set in your terminal (for example `$env:FOUNDRY_API_KEY = "..."`) always win.
2. Then the `.env` file: `SECURITY_ENV_FILE` if set, else `.env` in the current folder, else `.env` in the repo root.
3. Then the defaults above.

A `.env` file is read only by entry points (`tests.live_decision1`, `security_service.config`, and later
the HTTP service). Library code and the automated checks never read it, so a real `.env` cannot change
what a test does.

## The HTTP service

This is how Flwn calls the scanner. It implements the contract in `openapi.yaml` (version 1.1.0).

    python -m security_service.api --new-key     # make a key, and show the line to put in .env
    python -m security_service.api --check       # show the settings and any problem, without starting
    python -m security_service.api               # start it (Ctrl+C stops it)

Callers sign in with `Authorization: Bearer <key>`. Each key has a name and scopes: `scan` (create scans, delete them),
`fix` (request fixes), `read` (fetch results). A caller sees only its own scans: another caller's scan is "not found".

How a request is handled, in order: the key is checked first (so an unauthenticated caller learns nothing about
whether its request was well-formed), then the scope, then the caller's rate limit, then the size and shape of the
body. A bad request is answered at once with a `Problem` that never repeats what was sent; it never becomes a failed job.

Waiting: `Prefer: wait=N` holds the request up to N seconds (never more than `SERVICE_MAX_WAIT_SECONDS`) and answers 200
with the finished scan; otherwise 202 with a `Location` to poll. Retrying with the same `Idempotency-Key` and the same
body returns the original scan instead of starting another (and makes no second model call).

What it keeps, and what it does not: submitted code and results are held in MEMORY ONLY for `SERVICE_RETENTION_HOURS`,
removed earlier by `DELETE /v1/scans/{id}`, and gone when the service stops. Nothing is written to disk. Logs hold one line
per request (method, path, status, time, caller, request id): never a body, a key or a line of code.

What it does not do yet, said plainly:
- Fixes and verifications answer `501 not_implemented` (the corrector is the next step). `GET /v1/capabilities` has
  `features` so a client can ask first.
- It speaks plain HTTP. Put HTTPS in front of it (a reverse proxy or the platform's ingress) before it is reachable
  from anywhere but this computer; the default `SERVICE_HOST=127.0.0.1` is deliberately that safe.
- One instance only: scans, keys-to-scans, idempotency and rate limits live in this process. Running several copies behind
  a load balancer needs a shared store and limiter first, and a restart forgets every scan.
- No chunking of very large files for the model, and no per-key limits on how many scans a caller may hold.

Tests: `python -m tests.check_api` runs the real application in-process and checks every response against the contract
(status, content type, body), and that no key or submitted code appears in any error or log line. `python -m
tests.check_service` starts the real process from a `.env` and talks to it over real sockets.

## Decision-1 inside real scans

Until `CLASSIFIER_ENABLED=true`, Decision-1 is only used by the measuring tool, and a scan is Bandit plus the secrets
check. Switched on, every Python file in a scan is also sent, masked, to Decision-1 in ONE request with the 12 security
questions, and each category at or above the threshold becomes a finding in the report.

Try it on a file, switch off and on (PowerShell):

    python -m security_service.scan app.py                                       # rules only, the default
    $env:CLASSIFIER_ENABLED = "true"; python -m security_service.scan app.py     # Decision-1 as well

The exit code says what happened: 0 pass, 1 review_required, 2 block, 3 scan_failed, 4 could not start.

What those findings are:
- `model_suspicion` tier, medium severity, confidence at most medium, and no line: a decision model says "this file
  probably has this problem", it does not point at a line. They carry no code.
- They ask for human review (`review_required`). They never block: a model alone never blocks, even at 100% on
  everything. Only a rule-backed, high-severity, high-confidence finding blocks.
- If a rule already found the same problem in the same file, the two become one corroborated finding with the rule's
  line and severity, and the model is credited as a second source. A model that claims MORE than the rule (a LOW rule
  finding) stays as its own finding beside it.

If Decision-1 is down: by default the scan still finishes on the rules, and the report says so in the coverage and in
the decision reasons. With `CLASSIFIER_REQUIRED=true`, a scan that would have passed becomes `scan_failed` instead.
A failed rules engine is fatal to a pass either way. If it is switched on but Decision-1 is not configured, the
service refuses to start, so nobody believes they are protected by an engine that is not running.

Limits, stated plainly: Python only; a file larger than about 30,000 tokens is not assessed by the model (no chunking
yet; the rules still scan it and the report records the gap); the model sees masked code; it adds about half a
second and a fraction of a cent per file.

## Measuring the decision model (step 3, version 2)

`python -m benchmark.classifier_eval` sends labeled cases to Decision-1 with the security questions (one yes/no per
vulnerability category; none about secrets, which the secrets check owns), compares it with what the rules alone
catch, and tests whether a comment such as "approved by the security team" talks it out of a true finding.

Version 1 failed its gate on the 50 development cases. Reading the code showed most of that came from our own setup
(secret masking, three mislabeled test cases, loose question wording), so version 2 fixed those. A fix chosen after
seeing results cannot be judged on the same cases, so the verdict comes only from `benchmark/cases_heldout.py`: 39
new cases, written before any model saw them, with a pinned fingerprint so an edit cannot go unnoticed.

    python -m benchmark.classifier_eval --limit 3     # 1. smoke test on 3 development cases
    python -m benchmark.classifier_eval               # 2. development run: every number, no final verdict
    python -m benchmark.classifier_eval --heldout     # 3. THE final run. Do it once.

The gate, fixed in the code before the held-out run. At the single threshold 0.70, all four must hold: it finds
at least 80% of the vulnerable cases in the right category; it catches at least 1 case the rules do not alarm on; it
adds at most 2 false alarms beyond the rules; it loses at most 10% of its catches to a comment claiming a security
review. Passing only makes it a signal that asks for human review (a model alone never blocks). If it fails, the
classifier is parked and the scanner ships with rules only; the questions are not reworded and re-tested on that set.

Rules for the benchmark: every safe case must be clean for every category, not only the one it twins. Results go to
`classifier_eval_report.txt` and `classifier_eval_results.json` (both git-ignored, neither contains a key).

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
| `Cannot start: ...` or `Problems:` after you filled the file in | Your values were wiped (copying the template over `.env` overwrites it), you edited `.env.example` instead of `.env`, or Notepad saved `.env.txt` | Fill in `.env` again and never re-run the copy; if `.env.example` was edited, `git checkout -- .env.example`; then run the config check |

## Layout

    openapi.yaml                       the contract with Flwn (source of truth)
    .env.example                       committed template for your settings (the real .env is never committed)
    security_service/
      config.py                        settings from the environment and .env; `python -m security_service.config`
      version.py                       contract, service and policy versions
      core/                            stable: schema, decision policy, files, scan service, errors, redaction, patching, questions
      ports/                           stable interfaces: analyzer, llm, classifier, corrector
      adapters/                        swappable: bandit, secrets_check, llm_detector, decision1, classifier_detector, foundry_llm, llm_clients, fakes
      api/                             the HTTP service: gateway (all rules), app (FastAPI), auth, jobs, ratelimit; `python -m security_service.api`
      scan.py                          scan files from the command line
    benchmark/                         development cases, held-out cases, scoreboard, bake-off, classifier_eval (step 3)
    tests/                             run_all, check_contract, check_api, check_service, check_transport, check_layout, live_decision1

Rule of thumb: `core/` and `ports/` never change when a provider changes. Only `adapters/` and
configuration do. A new provider must pass the port's validation rules and clear the benchmark gate.

Other commands: `python -m tests.check_contract` (code against the contract, with real Bandit output),
`python -m benchmark.run_benchmark` (the 50-case Python scoreboard), `python -m benchmark.bakeoff`
(self-test of the model comparison harness).

## Status

Built and tested: the core, the ports, the Bandit, secrets-check, LLM-detector and Decision-1 adapters; Decision-1 as an
optional engine in real scans; the settings and `.env` support; the benchmark (50 development and 39 held-out cases) and
the held-out test of Decision-1 (passed, see `benchmark/results/`); the contract; the HTTP service for scans (keys and
scopes, rate limits, idempotency, wait or poll, retention, delete); and end-to-end tests over real sockets.

Run against the real service: Decision-1 (sign-in, request, reply, and the held-out test).

Not yet run against a real model: the LLM detector and the Foundry adapter.

Not built yet: the corrector (GPT-6 Astra) and the fix and verification services behind the 501s, the Flwn side of the
integration, chunking of large files for the model, a persistent job store and a shared rate limiter for running several
instances, TLS, and the C++, C# and JS lanes.

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
  Foundry" (updated 2026-10-09) and then by a real call (2026-10-23). Confirmed: endpoint path, request
  shape, API-key sign-in, and the reply format (`noul`, `choice`, `probabilities`, `confidence`, `usage`).
  Still not shown anywhere: an input-size limit, a rate limit, and any EU data zone. Microsoft's region
  table lists the model only as Global Standard and Data Zone Standard (no regional type); the US regions
  show for both, and the Europe rows must be checked in the portal before promising EU-only processing.
- The classifier sees MASKED code. In the first real call, a password assignment arrived as
  `DB_PASSWORD = "<REDACTED_SECRET>"` and scored only 0.62 for "contains a hardcoded password", and
  command injection scored 0.80. So secrets are the job of the deterministic secrets check (which reads the
  original code locally), and the classifier is used for what rules miss, not for secrets.
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
- Decision-1 in scans is OFF by default and OPTIONAL when on. Its findings are whole-file model suspicion at one flat
  medium severity (a model gives a probability, not a severity), capped at medium confidence, and they never block.
  The threshold is the one the held-out test validated (0.70); other values are accepted with a warning that they have
  not been measured. Passing that test means the model is worth using as a review signal, not that it is accurate in
  general; real Executor outputs are the next test.
- The service never starts without an API key, never runs unauthenticated, and listens on this computer only unless
  told otherwise. Keys are kept only as digests and compared in constant time; no message contains one.
- Scans are held in memory only, so a restart forgets them and the retention promise cannot be broken by a forgotten file.
  The cost is that it is one instance only; a persistent store is a later, deliberate step.
- An engine that raises instead of returning its failure is treated as a failed engine, never as a crashed scan, and only
  the type of its exception is recorded (the message may contain code).
- A secret found by pattern asks for human review but never blocks on its own: a pattern cannot tell a
  live key from the documented example key, and only HIGH confidence blocks. Masking is liberal (a
  missed secret leaks); reporting is careful (every report is an alarm). The known gap: a real secret
  assigned to an innocently named variable (for example `backup = "..."`) is neither reported nor masked.
- The secrets check runs on Python only, so a file in another language is never counted as scanned
  because of secrets coverage alone. Widen it together with each language's rules engine.
- When two rule engines agree on one issue they appear as one corroborated finding. A model can join a
  rule's finding only if it claims no more than the rule does, and it never raises the rule's severity or
  confidence; a model that claims more stands alone as a model suspicion.
