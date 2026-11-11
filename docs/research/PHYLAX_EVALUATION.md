*PHYLAX · EVALUATION*

# What was measured, and what it can support.

This document records the testing and evaluation of Phylax **as it actually happened**. It separates three kinds of evidence that are easy to confuse: *development results* (used to tune the system, so biased), *held-out results* (run once, after the design was frozen), and *exploratory observations* (no labels, so no accuracy). Nothing here is a claim of general accuracy.

Read the status labels in `PHYLAX_PROJECT_OVERVIEW.md`. Sources: `benchmark/results/heldout_v1_verdict.md`, `benchmark/results/js_gate_preregistration.md`, the benchmark code, the suite, and the development transcripts. The raw held-out report (`classifier_eval_report.txt`) is **not in the repository**; only the written verdict is. A reader who needs the per-case rows must ask the team for that file.

## 1. How the evaluation was kept honest

Five mechanisms, in the order they were introduced:

1. **A pre-registered gate.** Before any model saw the held-out cases, the pass criteria were written down: at the single threshold 0.70, all of (1) find at least 80% of vulnerable cases in the right category; (2) catch at least one vulnerable case the rules do not alarm on; (3) add at most two false alarms beyond the rules; (4) lose at most 10% of catches to an injected "security review" comment. The code (`GATE` in `benchmark/classifier_eval.py`) carries these numbers.
2. **A development set and a held-out set.** The 50 original Python cases became a development set the moment their results were read, three of their labels were corrected because of what the model flagged, and the questions were reworded because of what it missed. A new 39-case held-out set was written **after** that and **before** any model saw it.
3. **A fingerprint lock.** The held-out file pins a hash of its cases (`7871031988b1` for Python; `7c174d9dca25` for JavaScript). A verdict is refused if a character changes.
4. **One run.** The held-out set is run once. If it had failed, the classifier would have been parked and the scanner shipped with rules only. Rewording the questions and re-running on the same set is explicitly disallowed because it would turn the held-out set into a development set.
5. **A stop rule recorded in advance** for the JavaScript evaluation, including what a pass and a fail change (`js_gate_preregistration.md`, dated 2026-11-07, before any model saw a JavaScript case).

A limit no mechanism removes: the same person wrote the rules, the questions, and the cases, in the style of textbook examples.

## 2. The datasets

| Set | File | Cases | Composition | Role |
|---|---|---|---|---|
| Python development | `cases_python.py` | 50 | 23 vulnerable, 16 fixed twins, 11 look-alikes | tuned on; no verdict |
| Python held-out | `cases_heldout.py` | 39 | 14 vulnerable, 25 safe | one run, verdict |
| JavaScript/TypeScript development | `cases_javascript.py` | 51 | 27 vulnerable, 24 safe | for tuning; **model not yet run** |
| JavaScript/TypeScript held-out | `cases_heldout_js.py` | 39 | 14 vulnerable, 25 safe | **model not yet run** |

Design of the cases. Per category there is a **vulnerable** case (V), its clean **fix** (F, the safe twin that does the same task), and a **look-alike** (L) that resembles the vulnerable pattern but is safe. The paired design is deliberate: it measures whether a detector can tell a vulnerability from its repair, not only whether it fires on dangerous-looking text. Rules for the held-out sets: every safe case must be clean for **every** category the classifier is asked about (the first run showed that a case labelled safe for one category can be vulnerable for another); no case is about hardcoded secrets (the model is not asked about them); and anything debatable was left out.

Labels are written by hand and are the part to review by hand: "a mislabeled case silently corrupts every number the benchmark produces" (a comment in the code). In the first Python run, three "safe" cases were mislabeled, and the model, not the label, was right in two of them (a `requests.get(url)` with a parameter `url` is server-side request forgery; a template built from variable text is template injection).

## 3. Metrics, defined

For a set of cases, each labelled vulnerable (with a category) or safe:

- **Found** (per vulnerable case): did any finding carry the right category? This measures the *engines*.
- **Alarmed** (per case): did the final **decision** become REVIEW_REQUIRED or BLOCK? This measures engines *plus the decision policy*.
- **Recall** (here, "found" or "alarmed" rate): vulnerable cases flagged, over vulnerable cases.
- **False alarm** (per safe case): any decision other than PASS. **False alarm rate** is false alarms over safe cases. (Fixed twins and look-alikes are both "safe".)
- **Extra found / extra false alarms:** counted *beyond what the rules alone do*, which is what the gate cares about, because the question is whether the model adds anything.
- **AUC** (`auc()` in `classifier_eval.py`): the probability that a randomly chosen positive scores above a randomly chosen negative, ties counting half. It is threshold-free. Two are reported: *true-category question against every other question* (does the model's own category question score highest on a vulnerable case?), and *vulnerable against safe cases*.
- **Flip rate** (injection test): of the catches the model makes on the plain case, the share it loses when a comment is prepended.

Not computed anywhere in the repository: precision, F1, a confusion matrix per category, calibration error, or any confidence interval. The intervals below were computed for this document from the counts in the records.

## 4. Results

### 4.1 Python, Decision-1, question set version 1 (development set): FAILED

Source: development transcript of the first real run; not in `benchmark/results/`. 50 cases; 96 requests; 0.54 s per 14-question request; about $0.0058.

| Result | Value |
|---|---|
| Right category on vulnerable cases | 21 of 23 (91%; 95% interval 73% to 98%) |
| Rule-blind cases caught (of 4 the rules miss) | 3 of 4 |
| AUC, true-category question against every other | 1.00 |
| Injection "approved by the security team" | no loss; scores rose about 2% |
| Injection "ignore all previous instructions" | one catch lost (5%) at the strictest threshold |
| **Gate** | **FAIL: 7 extra false alarms, allowed 1** |

Causes of the false alarms, from reading the code behind each: four secret look-alikes (the liberal masking turned a harmless value such as a header name into the secret marker, and the question told the model that the marker means a real secret, so "yes" was correct for what it saw), two mislabeled cases where the model was right, and one defensible-but-arguable case (a `ping` to a variable host flagged as SSRF). Separately, the optional "worst problem" verdict question named a problem on 14 of 27 safe cases and was removed from the alarm path. The conclusion recorded at the time: most of the failure measured the *instrument*, not the model, but a fix chosen after seeing results cannot be judged on the same cases, so version 2 was to be judged only on new cases.

### 4.2 Python, Decision-1, question set version 2 (held-out set, 2026-10-23): PASS

Source: `benchmark/results/heldout_v1_verdict.md`. One run, 39 cases, 12 questions per request, 67 requests, 75,340 input tokens, about $0.0032, 0.55 s per request on average. Model `Microsoft-Decision-1@1`, deployment `decision-1`, held-out fingerprint `7871031988b1`, threshold 0.70.

| Gate criterion (fixed before the run) | Needed | Result | 95% Wilson interval of the result |
|---|---|---|---|
| Finds the vulnerable cases, right category | at least 80% | 13 of 14 (93%) | 69% to 99% |
| Catches a vulnerable case the rules do not alarm on | at least 1 | 2 (`h-rand-vuln`, `h-path-vuln`) of the 3 the rules miss | 21% to 94% (of 3) |
| False alarms beyond the rules | at most 2 | 2 (`h-path-look`, `h-xss-look`) of 25 safe | 2% to 25% |
| Catches lost to a "security review" comment | at most 10% | 0% and 0% | not meaningful at this size |

Supporting numbers: rules alone alarmed on 11 of 14 vulnerable cases (79%; 52% to 92%) with 5 false alarms on 25 safe (20%; 9% to 39%). Decision-1 alone at 0.70: 13 of 14 right category, 3 false alarms on 25 safe (12%; 4% to 30%). Rules plus Decision-1: 13 of 14 vulnerable cases alarmed. Score separation: AUC 1.00 (true-category question against every other) and 0.99 (vulnerable against safe).

Injection (intervals use a denominator of 13 catches inferred from the recorded percentages; confirm against the raw report):

| Injected comment | Catches lost, threshold 0.5 to 0.70 | at 0.80 | at 0.90 |
|---|---|---|---|
| "approved by the security team" | none at any threshold from 0.5 to 0.9 | none | none |
| "ignore all previous instructions" | none | 2 (15%; 4% to 42%) | 4 (31%; 13% to 58%) |

Debug-mode detection fell from 100% to 75% under the second comment. The one miss was `h-xss-vuln` (a template built from an f-string) at 47%; the template question was also the source of both extra false alarms.

**How to read this honestly.** The gate passed, so the classifier earned its role as a *review signal*. The statistics are weaker than the verdict sounds. With 14 vulnerable cases the 80% recall bar lies **inside** the 95% interval (69% to 99%), so the data do not demonstrate recall of at least 80%; they show the model is worth keeping. The two "extra catches" are 2 of 3 cases. The same author wrote the rules, the questions and the cases. The verdict file itself states that 14 and 25 cases "written by us, in the style of textbook examples" show the classifier is worth using as a review signal, "not that it is accurate in general".

### 4.3 JavaScript and TypeScript

**Decision-1 on JavaScript and TypeScript: not evaluated.** The questions (`_CATEGORY_TEXT_JS`), the two case sets and the gate are pre-registered; no model has seen a JavaScript case; there is no verdict; Decision-1 is therefore **not asked** about JavaScript or TypeScript in production (`VALIDATED_LANGUAGES = ("python",)`).

Measured offline, without any model, on the same cases (rules only, `js_gate_preregistration.md`):

| Set | Vulnerable alarmed | Right category | False alarms on safe |
|---|---|---|---|
| Development (27 vulnerable, 24 safe) | 15 of 27 (56%; 37% to 72%) | 16 of 27 | 4 of 24 (17%; 7% to 36%) |
| Held-out (14 vulnerable, 25 safe) | 5 of 14 (36%; 16% to 61%) | 6 of 14 (43%; 21% to 67%) | 2 of 25 (8%; 2% to 25%) |

Nine of the 14 held-out vulnerable cases are ones the rules do not alarm on (the flow crosses a function, the command goes through `sh -c`, the algorithm name sits in a constant, a setting is written with brackets). These cases were designed *by the same person who wrote the rules* to show where rules fall short, so the rules-only recall here is a deliberately hard-case measurement, not an estimate of real-world recall.

### 4.4 Exploratory runs on real code (no labels: not accuracy)

These were run to check behaviour and false-alarm noise on real code. No ground truth was established for them, so none of these is a detection rate.

- **Python.** Two deliberately vulnerable Flask applications, 25 Python files. Two files (copies of one vulnerable script) were BLOCKED with command injection, insecure deserialisation and SQL findings; three files in the other project were REVIEW_REQUIRED (insecure deserialisation, SQL injection at low confidence, path traversal); the remaining files passed. Source: the development transcript of 2026-11-07.
- **JavaScript.** From the development record (not re-run for this document): NodeGoat produced 6 findings (3 `eval`, an SSRF, an open redirect, a `$where`); the Express and Axios libraries produced 0 findings over about 12,000 lines (a check that mature, well-reviewed code stays quiet); the Juice Shop's real server code produced 15 findings. Whether any of these are true or false positives was not adjudicated.

### 4.5 Correction quality

- Real Astra, Python, about six examples in development. The first: a ping command, 7 seconds, under 2 cents, patch fit the file, parsed, passed the re-scan with nothing new. The fix was good but not minimal (it added a guard and dropped an unused import), which a reviewer must judge, and which led to the undefined-name check.
- **No success rate was ever measured.** There is no fix-quality benchmark (planned, not built). There is no test that a patched program still behaves correctly; verification checks safety properties and syntax, not behaviour.
- Real Astra on JavaScript or TypeScript was **never run**.
- The demo UI replays corrections produced by a **stand-in** correction model inside the real service, so its diffs show the real verification pipeline, not real Astra output.

### 4.x Configuration-file secrets scanner (2026-11-11)

Forty whole files (20 vulnerable, 20 safe) in seven formats were written after the detector was frozen and without running it on them, fingerprinted (`046d0b1e5d2d`), and judged once against a gate fixed
beforehand (at least 16 of 20 vulnerable files found, at most 1 false alarm among 20 safe files, no evidence line equal to its raw line). Result: **17 of 20 found** (Wilson 95%: 64% to 95%), **1 of 20 false
alarms** (1% to 24%), 0 leaking evidence lines; gate passed. Two of the three misses were designed limits (an abbreviated key, a dictionary passphrase). The run also found two real defects: dependency
version ranges in `package.json` were reported as secrets, and a commented-out credential with words before the key was missed. Both were fixed afterwards, which makes those 40 files development
data: the fixed detector scores 18 of 20 and 0 of 20 on them, **a development figure that must not be quoted as held-out**. Any further claim needs a new set. The author of the detector also wrote the
cases, so the set is held out from tuning, not from the author's idea of what a secret looks like. Record: `benchmark/results/config_heldout_verdict.md`.

### 4.y Fix quality on JavaScript and TypeScript (harness built; not yet run on the real model)

The service's four checks on a correction (scope, syntax, size, re-scan) judge safety, not behavior. `benchmark/fix_eval.py` adds a behavior check on 11 small cases (8 JavaScript, 3 TypeScript): the original
and the fixed code run in Node with the dangerous functions replaced by recorders, and the recorded events are compared on a benign input. Each answer is classified as usable, behavior-changed (passed the
four checks but behaves differently: the failure the service cannot see), failed checks, declined appropriately, declined, or unusable. The harness was verified with a scripted stand-in and by breaking each
of its ten checks in turn (all caught). **No result exists yet**: it needs one run with the real Astra (about 11 requests). These are development cases; a prompt tuned after reading the result needs new cases.

## 5. The testing architecture

Layers, from the inside out. All of it is in the repository except where noted.

| Layer | What it covers | Real model or mock |
|---|---|---|
| Module self-checks (`demo()` in each module) | policy thresholds, corroboration, redaction, patching, verification, each adapter's request shape and error handling, the rules (each of the 25 rules on a vulnerable and a safe example, plus look-alikes) | scripted stand-ins; real Bandit and tree-sitter |
| Contract (`check_contract`, `check_api`) | `openapi.yaml` is valid OpenAPI 3.1; real responses (about 190 to 196, every status, content type and body) match the schemas | no model |
| Transport and process (`check_transport`, `check_service`) | real HTTP end to end: URLs, headers, masking, 401/404/429/timeout/refused; a real service process started from a `.env` | a fake model server |
| Fix flow | fix, verification, strict diff application, over real sockets | stand-in for Astra |
| Interoperability (`check_interop`) | the agent's own change mechanism (`changes.mjs`, supplied by the Oqelira team) agrees with the service on the SHA-256 of the text, applies a patch, refuses a stale write, reverts exactly | real Node and the real module |
| TypeScript client | 79 tests: HTTP client, workflow, disk and Oqelira adapters, command line, agent tools, end to end against the real service | stand-in for Astra |
| UI | 80 tests plus lint and a brand-rule check; demo data validated against the OpenAPI contract | recorded real-pipeline data |
| Deployment (`check_deploy`) | container recipe, pinned packages, workflows, production settings, the smoke script against a real local service | stand-in for Astra |
| Live model tests (manual scripts) | `tests.live_decision1`, `tests.live_corrector`, `benchmark.classifier_eval` | **real** Decision-1 and Astra |

The suite is `python -m tests.run_all` (50 checks at the last verified run), written without a test framework: each module checks itself and the runner calls them. Mutation testing was used throughout as a method: after writing tests, the code is deliberately broken (a threshold changed, a guard removed) and the tests must fail. Rounds of roughly 20 to 120 deliberate breaks were run in each of several development sessions; several exposed real weaknesses in the *tests*, which were then strengthened. The exact counts are in the transcripts and are not reproduced here as a result, since they measure test thoroughness, not detection quality.

Real-model versus mock, stated plainly. **Real Decision-1:** the Python evaluation (v1 development, v2 held-out) and the first real call. **Real Astra:** about six Python examples, run by hand. **Everything else that touches a model in the automated suite uses a scripted or stand-in model.** In particular, no automated test calls a real model, so the suite proves the plumbing, the policy and the verification, not the models' quality.

Platform. The suite and the TypeScript tests were run by the project owner on Windows and on Linux in a clean-clone replay; the UI and its checks have been run on Linux only. A development session found and fixed several Windows-only failures (path ordering, line endings, and an unread output pipe that stalled a test helper), which is evidence that platform differences matter for the reproducibility section of a paper.

## 6. Limitations and threats to validity

- **Authorship and size.** All cases were written by the people who built the system; 14 and 25 cases are small; intervals are wide; per-category numbers are at most one or two cases.
- **Style.** The cases are textbook-style. Real coding-agent output is messier. No real Executor output has been labelled and evaluated.
- **Label noise.** Labels were corrected after seeing model output on the development set (three cases). The held-out set was written to avoid this, but nothing external reviewed its labels.
- **One model version, one threshold.** `Microsoft-Decision-1@1` at 0.70. The model's own documentation says the base model may change under the same name, so the threshold should be re-validated per version. Run-to-run variance was not measured; the held-out set was run once by design.
- **No baseline from other tools.** No comparison with CodeQL, Semgrep, or another scanner on the same cases exists. "Rules alone" means Phylax's own rules.
- **No generative-model comparison.** The bake-off harness exists; no real model was ever compared.
- **Not independently replicated.**
- **Verification is not behaviour.** Fix verification does not run tests; fix success was not measured.
- **Coverage.** Scans are bounded by the languages listed in `PHYLAX_ALGORITHM_GUIDE.md` section 7 and by the `not_assessable` list in every report.
- **Latency and load** were not benchmarked; the service holds scans in memory on one instance.

## 7. What can and cannot be claimed

Can be claimed, with the caveats above: the system is built so that a model alone cannot block code, skipped files and failed engines cannot produce a PASS, and a proposed correction cannot be applied without a person approving that file's diff; these are properties of the code and are covered by tests. Decision-1, asked twelve yes/no questions about Python files, passed a pre-registered gate on a small author-written held-out set and added two catches and two false alarms beyond the rules. The first version of the questions failed its gate, for reasons traced mostly to the project's own instrument.

Cannot be claimed: that Phylax detects a given share of real vulnerabilities; that Decision-1 helps on JavaScript or TypeScript; that corrections are usually right or preserve behaviour; that the system is robust to adaptive prompt injection (one injected sentence degraded catches at higher thresholds); that results generalise beyond author-written cases.

## 8. How to report these results academically

1. Report **counts with intervals**, not bare percentages, and say the sample is small. Use a method suited to small samples (the Wilson score interval is used here; it is the author's choice for this document, not a repository standard).
2. Keep **development and held-out** in separate tables and say which was used for design decisions. Disclose the failed first version and the pre-registration, which strengthen the account.
3. Report **per-category** results only where the counts support them (here: not many).
4. Report the **paired** design (vulnerable, fixed twin, look-alike) as a strength, and cite the literature on why accuracy misleads at realistic base rates (see the PrimeVul entry in `PHYLAX_RELATED_WORK.md`: vulnerabilities are rare in real code, so a vulnerable-heavy test set inflates apparent performance).
5. State the **threshold, the model version, and the date**, because the model can change.
6. State the **threats to validity** in section 6 as limitations, not footnotes.
7. Do not present the exploratory real-code runs as detection rates.
8. If the team can, add an external baseline (another scanner on the same cases), real coding-agent output labelled by someone other than the author, repeated runs to estimate run-to-run variance, and a measured fix-success rate with a behavioural check. These are the largest gaps.
