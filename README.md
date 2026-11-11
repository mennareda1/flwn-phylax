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
| `CLASSIFIER_LANGUAGES` | no | `python` | Languages Decision-1 is asked about. Add `javascript` (which covers TypeScript) only after `python -m benchmark.classifier_eval --language javascript --heldout` passes; until then it warns. |
| `CORRECTOR_DEPLOYMENT` | for fixes | none | The exact Name of the GPT-6 Astra deployment in Foundry (not the model's display name; no spaces). |
| `CORRECTOR_ENDPOINT`, `CORRECTOR_API_KEY` | no | the Decision-1 ones | Only if Astra is in a different Foundry resource. |
| `CORRECTOR_API` | no | `openai_v1` | Which route to call, `openai_v1` or `inference`; `tests.live_corrector --both` finds the one that works. |
| `CORRECTOR_REASONING_EFFORT`, `CORRECTOR_MAX_OUTPUT_TOKENS`, `CORRECTOR_TIMEOUT_SECONDS` | no | `low`, `8000`, `180` | Cost controls: Astra's thinking is billed as output. |
| `SERVICE_API_KEYS` | for the service | none | Who may call it: `name:scopes:key`, comma-separated. Make a key with `python -m security_service.api --new-key`. |
| `SERVICE_HOST`, `SERVICE_PORT` | no | `127.0.0.1`, `8080` | Where it listens. `127.0.0.1` means this computer only. |
| `SERVICE_RETENTION_HOURS` | no | `24` | How long submitted code and results are kept (in memory only). |
| `SERVICE_WORKERS`, `SERVICE_RATE_LIMIT_PER_MINUTE`, `SERVICE_MAX_WAIT_SECONDS` | no | `4`, `120`, `30` | Scans at once, requests per minute per caller, longest `Prefer: wait`. |
| `SERVICE_FIXES_ENABLED` | no | `false` | Turns on fixes in the service (needs the `CORRECTOR_*` settings; the service refuses to start without them). |
| `SERVICE_FIX_WORKERS`, `SERVICE_FIX_RATE_LIMIT_PER_MINUTE` | no | `2`, `10` | Fixes run in their own small pool, with a stricter per-caller limit, so they cannot starve scans or run up the bill. |
| `SCAN_MAX_FILES`, `SCAN_MAX_FILE_BYTES`, `SCAN_MAX_TOTAL_BYTES` | no | `50`, `200000`, `1000000` | Request limits. |
| `SECURITY_ENV_FILE` | no | | Path of a `.env` file to use instead of the default lookup. |

How settings are found, in order of priority:

1. Variables set in your terminal (for example `$env:FOUNDRY_API_KEY = "..."`) always win.
2. Then the `.env` file: `SECURITY_ENV_FILE` if set, else `.env` in the current folder, else `.env` in the repo root.
3. Then the defaults above.

A `.env` file is read only by entry points (`tests.live_decision1`, `security_service.config`, and later
the HTTP service). Library code and the automated checks never read it, so a real `.env` cannot change
what a test does.

## Verified fixes

    python -m security_service.fix app.py                          # scan, ask for a fix, verify it, print everything
    python -m security_service.fix src                             # a whole folder: every .py file in it (venv, .git, build... are skipped); at most 10 files are fixed per run
    python -m security_service.fix app.py --save-patch fix.diff    # also save the VERIFIED patch, then:  git apply fix.diff

It scans the files, asks the corrector (GPT-6 Astra) for a patch per file, and verifies each patch before calling it applicable:

- the diff is applied, strictly (no fuzz), to the exact file that was scanned, and what is verified is exactly the text a client will get;
- `scope`: only files of the scan changed; `syntax`: the code parses and uses no NEW undefined name (an import deleted while still used
  parses fine and passes a re-scan, then crashes: this catches it); `patch_size`: within `--max-lines` (default 40);
  `rescan`: the changed files are scanned again with the same engines, every requested finding must be gone and nothing new that a rule
  backs may appear (a new suspicion only a model has is listed for review, because a model alone never blocks);
- the outcome is `passed`, `failed`, or `inconclusive` (the re-scan could not run: never treated as passed); only `passed` is applicable.

Files and folders both work (`python -m security_service.scan src` scans a whole folder). Files are named in reports and patches relative to the folder you run the command in (else the git repository root, else the folder you named), never with a drive letter or an absolute path, so `git apply fix.diff` works from that folder.

Give it files or a whole folder (`python -m security_service.fix src --save-patch fix.diff`): a folder is searched for `.py` files, skipping `.git`, `venv`, `node_modules`, `build` and the like. Files are named relative to the folder you run it in (else the git root, else the folder you named), never by a full path, so the saved patch applies with `git apply` from that folder. At most 10 files are fixed per run, most severe first.

It never changes your files: you read the patch and apply it. A patch that failed verification is shown and, by default, not saved; `--save-unverified FILE` keeps it for review, marked UNVERIFIED inside the file. "Not confirmed" is not "wrong": a rule-based re-scan cannot confirm every correct fix (for example Bandit's SQL rule flags any query built with an f-string, even with a trusted table name), so a failed check names the rule and line that still fire, and the model is told what the re-scan looks for. Findings it did
not fix are listed (NOT FIXED) with the reason. A hardcoded secret is never fixed automatically: remove it and rotate it.
The same service is available through the HTTP service (below) when `SERVICE_FIXES_ENABLED=true`.

## The corrector (GPT-6 Astra)

The corrector turns a finding into a proposed fix. It has run against the real GPT-6 Astra (the first call below), and is used by
the fix tool and, when switched on, by the HTTP service, always behind the verification that decides whether a patch is applicable.

First real call, with one line in `.env` (`CORRECTOR_DEPLOYMENT=<the Name of your Astra deployment>`; the endpoint and key are
shared with Decision-1):

    python -m tests.live_corrector            # one real request on the configured route
    python -m tests.live_corrector --both     # try both routes, and say which to use

It sends only a built-in sample, shows the model, the time, the tokens (thinking included), the cost and the patch, and checks
the fix the way the fix service will: the patch fits the file, the patched code parses, and a re-scan shows the problem gone.

How a fix is asked for, and why:
- The model returns exact whole-line edits (`old` and `new`), not a rewritten file. That is cheaper (output is the expensive
  part), and it makes the scope checkable: only the lines in `old` can change, each edit names the finding it fixes, and an
  edit that does not match the file exactly, once, at the start of a line, is refused instead of guessed at.
- The code and the findings sit inside tags with a random name per request, and the model is told they are data. Code cannot
  forge the closing tag. This reduces prompt injection; it does not remove it. That is why the fix service re-scans the patched
  code and a person approves every patch.
- Secrets are masked before the code leaves, and an edit that touches a masked line is refused: removing a real secret is not
  automated, and the secret must be rotated anyway.
- Astra's rules, as we know them: `max_completion_tokens` (not `max_tokens`), no temperature, effort `low`/`medium`/`high`/`xhigh`,
  no tools (those need the Responses API). Thinking counts against the output cap, so a cap that is too small gives an empty answer,
  which is reported as such.

## Using Phylax from a coding agent: the review client (`clients/typescript/`)

Phylax stays a separate service that never touches your files. The way an agent uses it is an OPTIONAL review the user asks for after the agent has finished its task,
not a step inside the agent's loop. A small TypeScript client (`clients/typescript/`, see its README) runs the workflow: scan the chosen files, list the findings, let the
person choose which to correct, show each correction as a diff, apply it only after an explicit yes, then verify what is on disk. It reaches an agent through two small
interfaces (`FileChanger` and `Approver`), so it is not tied to Oqelira: Oqelira has an adapter built on its own `changes.mjs`, a plain-folder adapter works with any agent,
and a command-line tool (`phylax-review`) works with none. Run its tests with `python -m tests.check_ts_client` (needs Node 20+ and `npm install` once in that folder).

Which findings are offered a correction is decided by the service, per finding, in `finding.fix` (contract 1.4.0): medium severity and above yes; low and informational
reported only; a hardcoded secret never. It does not depend on the verdict: a medium finding is offered when the decision is only `review_required`, and a `block` does
not make a low finding eligible.

## Deploying it

Phylax ships as one container: `Dockerfile` (a pinned Python base, the exact package versions in `constraints-runtime.txt`, a non-root user, a health check, no secret baked in).
GitHub Actions runs every check on each push (`.github/workflows/ci.yml`), and publishes the image to the GitHub Container Registry when you push a version tag, after starting
the image itself and running `deploy/smoke.py` against it (`.github/workflows/publish.yml`). `deploy/azure/README.md` is the step-by-step guide for Azure Container Apps (run ONE
copy: scans are kept in memory), and `deploy/azure/production.env.example` lists every setting. After a deployment, `python deploy/smoke.py --url https://...` checks that it works.

Production setup: corrections ON (each one is a paid model call, with its own strict rate limit), Decision-1 ON for Python only (the languages that have passed a held-out
evaluation; every other language is covered by the rules alone until it passes its own). Phylax never changes a file, so switching corrections on does not let anyone change code
without a person approving it in the client. `python -m tests.check_deploy` keeps all of this honest.

## Applying a fix exactly (for tools like Oqelira's apply_file_change)

Oqelira's `applyFileChange` takes the WHOLE new file plus the SHA-256 of the file it expects to replace, not a diff, and refuses if the file
changed in between. Phylax returns what it needs (contract 1.2.0, additive):

- `coverage.scanned_files`: each scanned file's path and the SHA-256 of its text as submitted (UTF-8, line endings included).
- on each patch: `base_sha256` (the hash of the text that was scanned and patched), `corrected_content` (the whole file after the patch) and
  `corrected_sha256` (its hash). `unified_diff` stays for people and for `git apply`.

The client flow: snapshot the file on disk; if its hash is not the patch's `base_sha256`, the file changed after the scan, so scan again and
do not apply; otherwise ask a person, then call `applyFileChange({path, expected_sha256: base_sha256, content: corrected_content})`. Afterwards the
file hashes to `corrected_sha256`, and Oqelira's own revert restores the original (which hashes to `base_sha256` again).

Windows line endings: the model is shown normalized text, and a file whose every line ends in CRLF comes back with CRLF (the diff too, so
`git apply` takes it); a file with mixed endings comes back with LF. Before this, a fix on a CRLF file always failed (the model's edits never
matched the `\r\n` text). The hash is of the text exactly as submitted, so the client must send the file's text unchanged.

Limits that belong to the apply tool, not Phylax: it takes files up to 10,000 characters (40,000 bytes), so check `corrected_content` before sending
it; it refuses `.env`, key files and anything under `.git` or `.oqelira`. `tests/check_interop.py` runs Oqelira's real `changes.mjs` under Node
(a copy is in `tests/fixtures/`) and proves all of this on real files: equal hashes for LF, CRLF and non-ASCII text, a Phylax patch accepted, a stale
patch refused, and an exact revert. It needs Node and says SKIPPED without it.

## Configuration files (secrets only)

`.json .yaml .yml .toml .ini .properties .config .txt` files are checked for **hardcoded secrets and nothing else**, and every report says so: the files are listed under `coverage.limited_scope`
(contract 1.4.0) and the verdict's reasons say "N configuration or text file(s) were checked for hardcoded secrets only". A clean result for such a file says nothing about the rest of what it contains.

What it finds: `password: x`, `db.password=x`, `"api_key": "x"`, a password inside a connection URL (`postgres://user:secret@host/db`), inside a connection string (`Password=x;`) or a JDBC query
string, XML settings (`<add key="ApiKey" value="x"/>`), the known token formats, private-key blocks, and credentials left in a comment. What it leaves alone: references (`${DB_PASSWORD}`,
`{{ vault_x }}`, `ENC(...)`, `!secret x`), placeholders (`changeme`, `<your-password>`, `********`), keys that only mention a credential (`token_url`, `password_min_length`), dependency
version ranges, and a pure dictionary passphrase (`correcthorsebatterystaple`, a known false negative). The secret value is masked in every evidence line, quoted or not.

A secret is never corrected by editing code, in a config file or anywhere else: it is reported (as a review, never a block) with the advice to remove it and rotate it.
Folder scans (`python -m security_service.scan .` and the TypeScript client) pick these files up and skip lock files, minified JSON, `.env*` files and keys.

Measured once on 40 whole files written after the detector was frozen: 17 of 20 vulnerable files found, 1 of 20 false alarms (`benchmark/results/config_heldout_verdict.md`). The two defects that run
found were fixed afterwards, so those 40 files are now development data. Check it yourself: `python -m security_service.core.config_secrets` and `python -m benchmark.config_eval`.

## Measuring fix quality on JavaScript and TypeScript

The service's four checks on a correction (scope, syntax, size, re-scan) say the fix is *safe*; they cannot say it still *does the same thing*. `benchmark/fix_eval.py` measures that on 11 small cases
(8 JavaScript, 3 TypeScript): the original and the fixed code are run in Node with the dangerous functions replaced by recorders, and what they did is compared.

    python -m benchmark.fix_eval                  # self-test with a scripted stand-in: no model, no key, no cost
    python -m benchmark.fix_eval --real           # the real Astra on every case (about 11 requests) and a report in benchmark/results/
    python -m benchmark.fix_eval --real --repeat 3 --only fx-js-sql-concat

Needs Node on PATH (22.6 or newer for the TypeScript cases). These are development cases, not a held-out set: see the limits section of the report it writes.

## JavaScript and TypeScript

Phylax scans `.js .jsx .mjs .cjs .ts .tsx` as well as Python. Needs `pip install -r requirements.txt` (the parser packages; prebuilt, no compiler,
no Node). Without them JavaScript files are skipped and can never pass, and `python -m security_service.config` says so.

Why our own rules: the best-known free rule collection for these languages is licensed for internal, non-SaaS use only, and Phylax is
offered as a service, so we wrote our own on the tree-sitter parsers (MIT licence). Flwn's legal side should still confirm that choice.

What the 25 rules (`adapters/js_rules.py`) understand: real structure, not text (a comment that mentions `eval(` is nothing); constants
(`const CMD = "ls"; exec(CMD)` is fine); user input one hop (`const id = req.query.id` makes `id` input); where a name came from (`exec` is a
command sink only if it came from `child_process`); TypeScript (`as`, `!`, generics, decorators, JSX in a .ts file). Only unambiguous
patterns can block (`eval` of a variable, `exec` of a built string, `shell: true`, `rejectUnauthorized: false`, `new Function`, node-serialize);
everything else asks for review.

What it does not do, said plainly: it follows nothing across functions or files, and cannot tell a sanitized value from an unsanitized one
beyond a few simple guards (so Decision-1 is meant to find what it cannot); the verifier checks that a fixed JavaScript file PARSES, but not
that it uses no undefined name (that needs scope analysis), and says so in the result: run the project's build or tests after applying;
and Decision-1 is not asked about JavaScript until it has passed its own held-out test (see below), so until then JavaScript files are covered by
the rules alone.

Decision-1 on JavaScript and TypeScript: the twelve questions are written for the language (`_CATEGORY_TEXT_JS`), judged the way the Python set was.
`benchmark/cases_javascript.py` (51 cases) is for tuning; `benchmark/cases_heldout_js.py` (39 cases, nine vulnerabilities the rules cannot see,
fingerprint-locked) is for one final run. The gate, the procedure and what a pass or a fail changes were written down before any model saw a case:
`benchmark/results/js_gate_preregistration.md`. Run `python -m benchmark.classifier_eval --language javascript --limit 3`, then without `--limit`
for a development run, then (once, after the wording is frozen) with `--heldout`. A pass lets `CLASSIFIER_LANGUAGES=python,javascript` stop warning
(after `VALIDATED_LANGUAGES` in `config.py` is updated); the model still only asks for review and never blocks. The rules alone score 6 of 14 on the
held-out set, so the model has to add something to pass.

Folders: `python -m security_service.scan src` and `...fix src` find JavaScript and TypeScript files too, skipping `node_modules`, `vendor`,
`dist`, `build`, `.next`, minified or bundled files (`*.min.js`, `*.bundle.js`) and declaration files (`*.d.ts`).

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

Fixes and verifications (`POST /v1/scans/{id}/fixes`, `POST /v1/verifications`, and `GET` for each) work the same way as scans: the key is
checked first, a retry with the same `Idempotency-Key` returns the same result with no second model call, and `Prefer: wait=N` waits or you poll.
Both need a COMPLETED scan of the same caller (`409 scan_not_completed` otherwise; someone else's scan is "not found"). A fix needs the `fix`
scope and fix mode on; it asks the corrector for a patch per file and then VERIFIES it itself, so `applicable` is true only when verification
passed, and nothing is ever applied by the service. A verification needs the `scan` scope and checks a correction the caller wrote (up to 200
changed lines). A scan may hold only 5 fix requests (`409 fix_limit_reached`: waiting will not help). Fixes and verifications live as long as
their scan and are deleted with it.

What it keeps, and what it does not: submitted code and results are held in MEMORY ONLY for `SERVICE_RETENTION_HOURS`,
removed earlier by `DELETE /v1/scans/{id}`, and gone when the service stops. Nothing is written to disk. Logs hold one line
per request (method, path, status, time, caller, request id): never a body, a key or a line of code.

What it does not do yet, said plainly:
- Fixes are OFF unless `SERVICE_FIXES_ENABLED=true`, because every fix request is a paid model call; off, they answer
  `501 not_implemented`. `GET /v1/capabilities` has `features` so a client can ask first.
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
    python -m security_service.scan src                                          # a whole folder
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

Run against the real GPT-6 Astra: the corrector (`python -m tests.live_corrector`, both routes, a verified fix).

Run on real code with the real Astra: the fix and verification services (`python -m security_service.fix`), on a deliberately vulnerable app, with every patch attacked before and after.

Built and tested end to end over real sockets, against a test double of Astra: the fix and verification endpoints of the HTTP service. Not yet run with the real Astra through the service.

Built for exact apply: file hashes in the scan report, the whole corrected file and both hashes on every patch, Windows line endings preserved, all tested against Oqelira's real change code.

Built for JavaScript and TypeScript: our own 25 rules, the secrets check, folder scanning, the verifier's syntax check, language-aware instructions to the corrector, all tested on a deliberately vulnerable Node app (NodeGoat).

Built for Decision-1 on JavaScript and TypeScript: the questions, 51 development and 39 held-out cases, a language switch in the evaluation, and a setting that keeps it off until it passes. NOT yet run against the real model.

Built for configuration files: the secrets-only lane (`.json .yaml .yml .toml .ini .properties .config .txt`), explicit coverage in every report, a 40-file held-out measurement, folder scanning in both tools.

Built for fix quality: a Node-based behavior check and 11 JavaScript and TypeScript cases (`benchmark/fix_eval.py`), self-tested; NOT yet run against the real Astra.

Not built yet for JavaScript and TypeScript: the result of Decision-1's held-out test (waiting for a real run), the undefined-name check, and a measured Astra fix rate (waiting for a real run). Not built yet: Java, C#, C.

Not built yet: the measured fix-quality test (the pass/fail rule fixed first, then new cases), an optional behavior check that runs a project's own tests, the Flwn side of the
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
- GPT-6 Astra may process submitted code globally (decided by the project owner, 2026-10-31): the corrector is allowed on a Global Standard
  deployment, so code leaves the EU for fixes. Secrets are masked before it leaves. Flwn's own terms to its customers should say so.
- A fix is applicable only when verification PASSED; a re-scan that cannot run is inconclusive, never a pass. Nothing is ever applied by Phylax.
- The corrector asks for exact whole-line edits, not a rewritten file; anything that does not fit the file exactly is refused.
  It never applies a patch. A fix is offered only after the fix service parses and re-scans it, and a person still approves.
- JavaScript and TypeScript rules are our own, on MIT-licensed parsers, because the common rule collections exclude SaaS use. The secrets check is
  widened to a language only together with a rules engine for it, so a file never counts as scanned on secrets alone.
- A secret found by pattern asks for human review but never blocks on its own: a pattern cannot tell a
  live key from the documented example key, and only HIGH confidence blocks. Masking is liberal (a
  missed secret leaks); reporting is careful (every report is an alarm). The known gap: a real secret
  assigned to an innocently named variable (for example `backup = "..."`) is neither reported nor masked.
- The secrets check runs on Python only, so a file in another language is never counted as scanned
  because of secrets coverage alone. Widen it together with each language's rules engine.
- When two rule engines agree on one issue they appear as one corroborated finding. A model can join a
  rule's finding only if it claims no more than the rule does, and it never raises the rule's severity or
  confidence; a model that claims more stands alone as a model suspicion.
