*PHYLAX · PROJECT OVERVIEW*

# What Phylax is, and why it exists.

This is the first of six documents prepared for the teammate who will write the academic review paper on the algorithms, models and technologies behind Phylax. It explains the purpose and design principles in plain language. The detail is in the others:

| Document | Read it for |
|---|---|
| `PHYLAX_PROJECT_OVERVIEW.md` (this one) | purpose, principles, status of every component, what changed from the plan, a glossary |
| `PHYLAX_ALGORITHM_GUIDE.md` | how every detection technique, the decision engine and the correction workflow work |
| `PHYLAX_TECHNICAL_ARCHITECTURE.md` | components, interfaces, data flow, diagrams, failure scenarios, security boundaries |
| `PHYLAX_EVALUATION.md` | tests, benchmarks, metrics, results with confidence intervals, limitations |
| `PHYLAX_RELATED_WORK.md` | algorithmic background, verified references, research gaps |
| `REVIEW_PAPER_HANDOFF.md` | a self-contained starting point for the paper |

## How these documents were produced, and how far to trust them

The repository was audited on 2026-11-11: the modules, the interfaces, the configuration, the dependencies, the tests, and the evaluation records in `benchmark/results/`. The development transcripts were searched for numbers and decisions the repository does not hold. **The code and the verdict files outrank anything remembered from discussions.** Nothing was assumed to be built because it was discussed. The application code was not modified to produce these documents.

References were checked against the web on the same date. Entries marked **verified** were found on a publisher, arXiv, or index page that confirmed their authors, venue and identifiers; entries marked **not yet verified** are bibliographic details from memory and must be checked before they are cited. The related-work document says which is which for every entry.

### Status labels used in all six documents

| Label | Meaning |
|---|---|
| **REAL MODEL** | implemented, and run against the real model at least once |
| **SCRIPTED ONLY** | implemented and tested, but only with a scripted or stand-in model |
| **NOT WIRED** | implemented, but not part of the running pipeline |
| **PRE-REGISTERED** | the test is written and the pass criteria fixed, but it has not been run |
| **PLANNED** | discussed or designed, not built |

## 1. What Phylax is

Phylax is an **independent security-review service for code written by AI coding agents**. A caller (a coding agent such as Oqelira, a terminal, or a web screen) sends it source files. Phylax scans them with deterministic static-analysis rules and, optionally, a small decision model. It returns a **verdict** (PASS, REVIEW_REQUIRED, BLOCK, or SCAN_FAILED), a list of findings, and a precise statement of **what was and was not checked**. If the person asks, it can propose a **correction** as a diff, check that correction again, and return it for the person to approve. The service never changes a file.

In one sentence: *rules decide, a model advises, a person approves, and nothing is applied without that approval.*

## 2. The problem

Coding agents write code faster than people review it. Published studies of AI code assistants give two reasons to put an independent check between an agent and a repository. First, assistants have been shown to produce vulnerable code: in one study, about 40% of 1,689 programs generated for 89 security-relevant scenarios were vulnerable (Pearce et al., 2022; assistants and models have changed since, so this is evidence of a risk, not a current rate). Second, assistants change how people review: in a controlled user study, participants with an AI assistant wrote less secure code and were more likely to believe their code was secure (Perry et al., 2023). Together these suggest that code an agent has just produced is code whose author and reviewer both have reasons to be over-confident.

Hence the design requirement: **the reviewer must not be the author.** A security check that shares the generating agent's context, prompt and incentives is not independent.

## 3. Relationship to Oqelira

Oqelira is the team's AI vibe-coding agent, written in TypeScript. Phylax is its **optional** security companion, not a stage of its execution loop. The original plan, during early design, was an automatic scan of agent output inside the Flwn AI engine's pipeline; the project owner changed this to an **explicit, user-requested workflow**: the agent finishes; the person asks for a scan; Phylax scans; the person chooses findings to correct; a correction is proposed; the person approves each diff; the host applies it through *its own* file-change mechanism; Phylax verifies what is on disk.

Phylax must not depend on Oqelira. The code reflects this: a host-neutral `FileChanger` interface, with one adapter built on Oqelira's real change mechanism (supplied by the Oqelira team and tested against it), one for plain disk, and the service itself knowing nothing about any agent. **Mapping Phylax's agent tools onto Oqelira's own tool definitions is not done**; it waits for Oqelira's tool and approval definitions.

## 4. Why an independent service

- **Independence of judgement** (section 2): a separate component with its own rules cannot be steered by the agent's prompt, and a person can trust that the check was not written by the thing being checked.
- **A credential boundary.** The model credentials live only in the service's environment. A prompt-injected agent cannot read them.
- **Replaceable providers.** The core talks to four interfaces; the models are adapters. The contract with callers does not change when a provider does.
- **Separate lifecycle and cost.** Corrections are paid model calls with their own rate limits and workers; scanning is cheap and local. They scale and fail differently.
- **Reuse.** Any agent, a terminal and a web screen can call the same service.

## 5. Why the service must not touch user files

1. **Least privilege.** A service that cannot write cannot be tricked into writing. The attack surface of "a scanner that edits your repository" is exactly the code it is scanning.
2. **A clear approval boundary.** Approval lives in the client, where the person is. The service has no concept of "apply".
3. **Exactness.** Only the host knows the file's real bytes, line endings and revert mechanism. The service returns the corrected text with SHA-256 hashes; the host refuses to write if the file changed since the scan, and reads the result back for verification.
4. **Auditability.** Everything the service says is a proposal with evidence; everything that changes a file is the host's recorded action.

## 6. Four concerns kept apart

| Concern | Component | Input to output | Who is authoritative | Why separate |
|---|---|---|---|---|
| **Detection** | engines (Bandit, our JS/TS rules, the secrets check, optionally Decision-1) | code to findings with evidence | rules for blocking; the model only for review | each engine can be improved, replaced or switched off alone |
| **Decision** | `core/policy.py` | findings and coverage to a verdict | a pure function, no model | it must be explainable and testable: "no model is ever asked 'is this safe?'" |
| **Correction** | Astra, via the fix service | finding and file to edits to a diff | no one: a proposal | a model's output is a claim, so it is verified, never trusted |
| **Verification** | `core/verification.py` | corrected files to four checks and an outcome | the service's own checks | the same standard applies whoever wrote the fix |
| **Approval** | the client (a person) | diff to yes or no | the person | consent must be explicit, per file, outside the service |

Merging these would be the usual way such tools go wrong: if the model that detects also decides, a comment in the code can talk it out of a finding; if the corrector also verifies, it marks its own work; if approval is automatic, the system is an unattended code-rewriter.

## 7. Traditional static analysis and an AI-assisted review system

*Traditional static analysis* parses code and matches it against hand-written rules. It is deterministic, explainable, fast, and cheap, and it is limited to the patterns someone wrote down; it reports look-alikes and misses disguised or cross-function problems.

An *AI-assisted* system adds a learned component. Learned detectors can generalise beyond a fixed pattern, but they are probabilistic, can be sensitive to wording and to text inside the code, and are harder to explain. Published evaluations of large language models as vulnerability detectors report high false-positive rates, non-deterministic answers, unfaithful reasoning, and brittleness to trivial code changes (Ullah et al., 2024), and report that benchmark numbers overstate real-world performance when datasets are leaky or unrealistic (Ding et al., 2025).

Phylax is a **hybrid with an asymmetric trust rule**: deterministic rules may block; the model may only ask for human review. The model used is not a generative chat model but a **decision model that returns probabilities for yes/no questions**, which removes the free-text reasoning that the studies above found unreliable, at the price of explanations and line numbers. The detail is in the algorithm guide.

## 8. Scope and non-claims

Phylax is a **review signal**, not a guarantee. A PASS means "nothing reached the threshold in the checks that ran on the files that were scanned". Every report lists what no scan can judge: authentication and authorisation logic, data flow across services and files that were not submitted, vulnerabilities in third-party dependencies, and deployment and runtime behaviour. It does not execute code or tests. It does not replace penetration testing, code review by a person, or dependency scanning.

## 9. Implementation status

| Component | Status | Notes |
|---|---|---|
| Scan service, policy, schema, files, masking | implemented, tested (no model needed) | the logic a paper can describe with certainty |
| Bandit lane (Python) | implemented, tested with the real tool | hardening partly done: memory and network limits still "to do" |
| Original JavaScript and TypeScript rules (25) | implemented, tested on examples and real code | rules-only recall on hard cases measured offline |
| Secrets check | implemented, deterministic | confidence always medium, so it never blocks |
| Decision-1 classifier, Python | **REAL MODEL**; held-out gate passed 2026-10-23 | small, author-written test set |
| Decision-1 classifier, JavaScript and TypeScript | **PRE-REGISTERED**; not asked in production | model has not seen a JavaScript case |
| Generative LLM detector and bake-off harness | **NOT WIRED**, **SCRIPTED ONLY** | no real generative model was ever compared |
| Astra corrector, Python | **REAL MODEL** on about six examples | no success rate measured |
| Astra corrector, JavaScript and TypeScript | **SCRIPTED ONLY** (stand-in) | never run against real Astra |
| Fix service and verification (four checks) | implemented, tested with stand-ins | JS/TS lacks the undefined-name check |
| HTTP service (keys, limits, jobs, idempotency, retention) | implemented, contract-tested | memory-only, one instance |
| Container, CI, publish workflow | implemented; image published to the registry | **not deployed to Azure**; deployment guide untested |
| TypeScript review client | implemented, 80 tests | adapters for disk and for Oqelira's change mechanism |
| Agent tools (scan, propose, apply) | implemented, host-neutral | **not mapped onto Oqelira's tool system** |
| UI | implemented as an **offline demo** | recorded data, stand-in model; live mode **PLANNED** |
| Configuration and text file scanning (secrets only) | implemented; 40-file held-out run 2026-11-11: 17 of 20 found, 1 of 20 false alarms | two defects found by that run were fixed afterwards, so those files are now development data |
| Fix-quality harness (behavior check) for JavaScript and TypeScript | implemented and self-tested; **not yet run against real Astra** | 11 development cases; needs the owner's Azure key |
| Java, C#, C | **PLANNED**, not started | order agreed with the owner |
| Chunking for large files, persistence, horizontal scale | **PLANNED** or deliberately omitted | |

## 10. Original architecture against the current implementation

| In the early design | Now | Reason or note |
|---|---|---|
| A decision model called "Jev" (TypeSafe), pinned to a 1.13 version | **Microsoft-Decision-1 on Foundry** | secondary sources describe the two as using a compatible request format; whether they are the same model is not established. The adapter targets Decision-1 |
| Scanning inside the Flwn AI engine's pipeline, automatically | **an optional service called on the person's request** | the owner changed the approach |
| "Rules keep a veto until the model passes a promotion test" | model **never** blocks; the promotion test became the held-out gate, and passing only grants a review role | stronger than first proposed |
| A role-to-provider registry in YAML (`providers.yaml`, `policy.yaml`) | environment variables and constants in code | simpler; the YAML files were not built |
| Chunking long files by function | not built; a file over about 30,000 tokens is not assessed by the model | rules still scan it, and the report says so |
| An optional LLM detector, settled by a bake-off | implemented, **not wired**; the bake-off never ran with a real model | an open research question |
| Verification = parses, re-scan, small patch | plus a **scope** check and, for Python, an **undefined-name** check | the latter added after a real Astra output removed an import |
| A fix-quality benchmark | not built | no success rate exists |
| A persistent store | memory only, 24-hour retention, one instance | deliberate for the first version |
| Data region question for Astra (EU) | unresolved | Astra is offered only as Global or US Data Zone in Foundry |
| Secrets masked as the first step | masked at the **boundary to any model**; local engines read raw text | a design choice; stated in the architecture document |

## 11. A first glossary

- **SAST** (static application security testing): analysing source code for security flaws without running it.
- **CWE:** the Common Weakness Enumeration, a catalogue of weakness types with numeric identifiers (for example CWE-78, OS command injection).
- **Injection:** untrusted input that ends up interpreted as code or a command (SQL, shell, template, script).
- **Source, sink, taint:** a *source* is where untrusted data enters; a *sink* is a dangerous operation; *taint analysis* asks whether data can flow from the first to the second.
- **Severity / confidence:** how bad the problem would be / how sure the detector is. Kept separate throughout.
- **False positive / false negative:** a report of a problem that is not there / a missed problem.
- **AST / CST:** a tree representing the structure of source code (abstract, or concrete including all tokens).
- **Held-out set:** test cases not used to design or tune the system, run once for the verdict.
- **AUC:** the probability that a random positive scores above a random negative; threshold-free.
- **Calibration:** whether a probability of 0.8 corresponds to being right about 80% of the time.
- **Prompt injection:** text inside the data a model reads that tries to change its instructions.
- **Human-in-the-loop:** a person must approve an action before it takes effect.
- **Evidence tier:** in Phylax, whether a finding rests on a rule, on a model alone, or on both.
