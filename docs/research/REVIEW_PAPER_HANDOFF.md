*PHYLAX · REVIEW PAPER HANDOFF*

# Starting the review paper.

This is written for the teammate who will write an academic review paper on the algorithms, models and technologies behind Phylax. It is self-contained: you can start from this page. It points to the five other documents for depth, and it is blunt about what Phylax's own evidence can and cannot support.

## 0. Read this first

1. **Position the paper as a review with a worked design example, not as a system paper with performance claims.** Phylax's evaluation is small and author-written (14 vulnerable and 25 safe held-out cases for Python; none for the model on JavaScript). It supports a *design argument*, not a benchmark result. The strong, defensible content is the design reasoning, the literature, and the honest evaluation methodology.
2. **Verify every reference before citing it.** Eight papers and the vendor documentation were verified on 2026-11-11; two more papers are *partly* verified (a missing DOI, or a DOI seen only on a secondary index); a longer list is *not yet verified* (`PHYLAX_RELATED_WORK.md`, sections 2 and 3). A search result confirms that a paper exists and what its abstract says. Read each paper before relying on it.
3. **Ask the team for four things** the repository does not hold: the raw held-out report from 2026-10-23 (only the written verdict is in the repository); the first, failed Python evaluation's report (only a transcript summary exists); the JavaScript evaluation, which has not been run; and the current status of the Oqelira integration (the tool mapping is not done).
4. **Do not repeat unverified claims**: that the decision model is post-trained from a particular open model, has a particular context length, or is the same as the model named in early design notes. These come from secondary sources or are unestablished (see section 10).

## 1. Suggested title

Pick one, or combine:

- *Rules Decide, Models Advise, People Approve: A Review of Hybrid Security Review for AI-Generated Code*
- *Independent Security Review of Agent-Written Code: Static Analysis, Decision Models and Human Approval*
- *Beyond "Is This Code Safe?": Fail-Closed Verdicts, Evidence Tiers and Verified Repair in AI-Assisted Security Review*

## 2. The research problem

AI coding agents produce code faster than people can review it, and published studies show both that assistants can produce vulnerable code and that people using them over-estimate its security. Existing tools for reviewing that code are either deterministic static analysers (explainable but limited to written patterns) or learned and generative models (more flexible but probabilistic, sensitive to wording and to text inside the code, and, in published evaluations, unreliable as sole detectors). **How should these be combined so that the result is trustworthy enough to sit between an agent and a repository, and how should automated repair be bounded?**

## 3. Motivation

- Evidence of risk: Pearce et al. (2022); Perry et al. (2023) (both verified).
- Evidence that LLM-only detection is not ready, and that benchmarks mislead: Ullah et al. (2024); Ding et al. (2025) (both verified).
- Evidence that static-analysis tools fail socially, through false positives and presentation: Johnson et al. (2013) (verified).
- Evidence that repair needs checking: Le Goues et al. (2019); Pearce et al. (2023) (both verified).
- Phylax as a concrete design that responds to these, with its failures recorded.

## 4. Suggested research objectives

1. Survey the techniques for detecting vulnerabilities in source code (rule-based, learned, LLM-based, hybrid) and state what each can and cannot establish.
2. Analyse how published work treats confidence, calibration and decision policy when a model's output feeds a security verdict.
3. Analyse automated repair of vulnerabilities with language models and the verification it needs.
4. Analyse how human approval and coverage semantics are designed in AI-assisted security tools.
5. Use Phylax as a worked example of design choices and their documented consequences, including negative results.
6. Identify gaps and an evaluation protocol for such systems.

## 5. Suggested structure

| Section | Content | Main sources in this repository |
|---|---|---|
| 1 Introduction | the problem, motivation, contribution, scope | overview, section 2 |
| 2 Background | vulnerabilities and weakness taxonomies; static analysis (parsing, patterns, taint; undecidability); learned and LLM detection; prompt injection | related work, sections 1.1, 1.2, 2.6 |
| 3 Detection techniques compared | rule-based, learned, LLM, decision-model, hybrid; a comparison table | related work 1.1 to 1.3; algorithm guide sections 3 and 4 |
| 4 From findings to a verdict | evidence tiers, corroboration, confidence thresholds, calibration, risk-based policy, fail-closed coverage | algorithm guide section 5; related work 1.4, 1.5 |
| 5 Repair and verification | LLM repair, constrained edits, the four checks, overfitting, what verification cannot show | algorithm guide section 6; related work 1.6, 1.7 |
| 6 Human-in-the-loop | approval gates, over-trust evidence, interface design | related work 1.8; architecture section 8 |
| 7 Case study: Phylax | architecture, decisions, the plan versus reality, evaluation method and results with intervals, failures | overview, architecture, evaluation |
| 8 Evaluation methodology | pre-registration, held-out sets, paired design, intervals, threats to validity; what a rigorous evaluation of such a system needs | evaluation sections 1, 3, 6, 8; Ding et al. |
| 9 Open problems | the gaps | related work section 4 |
| 10 Conclusion | | |

## 6. Algorithms and technologies to investigate

Static analysis: abstract syntax trees, tree-sitter's concrete syntax trees, AST visitors (Bandit), source-sink-taint reasoning (and Phylax's one-hop approximation), constant propagation by "bound exactly once". Learned detection: sequence and graph models, fine-tuned code language models, prompted LLMs. The **decision model**: typed questions (yes/no, choice, score), probability outputs, calibration, thresholds tied to versions. Decision logic: ordinal severity and confidence, evidence tiers, corroboration, fail-closed coverage. Repair: generate-and-validate, constrained whole-line edits, strict diff application. Verification: scope, parse, undefined-name check (Python: `ast`, `symtable`), patch size, re-scan with the same engines. Safety: masking before external calls, random tag names, `--ignore-nosec`, no endpoint that writes files, hash-checked atomic apply.

## 7. Comparisons worth making in the paper

1. **Where the trust sits.** Rules block, a model asks for review. Compare with calibrated joint scoring, model-assisted static analysis (IRIS-like, unverified), and model triage of alerts. State what each assumes about the independence of errors.
2. **Output form.** Typed probabilities (no reasoning, no line) against free-text LLM reasoning (explanations that may be unfaithful, Ullah et al.).
3. **Evaluation design.** Paired vulnerable, fixed and look-alike cases against single-label datasets (Ding et al.: base rate, leakage, label noise, chronological splits).
4. **Repair oracles.** Static re-scan (Phylax) against test-based and specification-based oracles, and the plausible versus correct distinction.
5. **Coverage semantics.** "PASS means nothing found by the checks that ran" and fail-closed on skipped files, against tools that report only what they found.
6. **Per-language lanes.** Why one rule set cannot serve every language, and how Phylax gates a model per language with a held-out test.

## 8. Research gaps

Section 4 of `PHYLAX_RELATED_WORK.md` lists nine. The four most useful for a review: decision models with typed probabilities as vulnerability classifiers; asymmetric-trust hybrids against alternatives; the false-confidence rate of static verification of model-generated patches; and robustness of review models to prompt injection in the code they read. **Search the literature before claiming any is unstudied.**

## 9. What Phylax can legitimately contribute to a review

Frame these as *design contributions and documented lessons*, not as measured improvements:

- A concrete policy in which a model **cannot** block, with the exact logic and the properties it enforces (algorithm guide section 5).
- **Evidence tiers and corroboration** as a way to make a hybrid's output auditable, and a merge rule under which a model can never raise severity.
- **Coverage-aware fail-closed verdicts**: skipped files and failed engines can never produce a PASS.
- The **verified-proposal pipeline**: constrained edits applied strictly to the scanned bytes, four checks, a service with no write path, and a client that refuses without per-file approval.
- A **disciplined evaluation process** in a small project: pre-registered gate, fingerprint-locked held-out set, a stop rule, and a recorded failure of the first version with its causes (most traced to the project's own instrument).
- An example of **gating a model per language** on its own held-out evidence.

## 10. Limitations that must be acknowledged

- The evaluation is small and **written by the system's authors** (14 vulnerable and 25 safe held-out cases), in textbook style; a 95% interval on 13 of 14 is 69% to 99%, and the gate's 80% bar lies inside it. Report counts with intervals (`PHYLAX_EVALUATION.md`).
- The **model has been evaluated for Python only**; JavaScript and TypeScript were pre-registered but never run. The correction model was run for real on about six Python examples; **fix success was never measured**, and verification does not run tests or check behaviour.
- **No generative-model comparison**, no external baseline tool, no run-to-run variance, no calibration measurement, no real coding-agent output evaluated, no independent replication.
- One injected sentence lowered catches at thresholds above 0.70: prompt injection is **not solved**.
- Coverage is bounded: Python, JavaScript and TypeScript are analysed; configuration and text files are checked for hardcoded secrets only; no cross-function or cross-file data flow; no dependency analysis; HTML, CSS, Java, C#, C not scanned.
- The service is **not deployed** to a hosting platform; scans live in memory on one instance; the Oqelira tool mapping and the UI's live mode are not built.
- Facts that are **not established**: the model's base model, context length and pricing (secondary sources); whether the early-design model and Decision-1 are the same model; the legality of reusing a third-party rule collection (a licensing concern noted in development, never reviewed by a lawyer).

## 11. Suggested keywords

static application security testing; vulnerability detection; large language models; decision model; calibrated probabilities; hybrid analysis; evidence corroboration; fail-closed verdict; automated vulnerability repair; patch verification; prompt injection; human-in-the-loop; AI-generated code security; coding agents.

## 12. References to start with

**Verified on 2026-11-11** (read each before citing; full entries in `PHYLAX_RELATED_WORK.md` section 2):

1. Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., Karri, R. (2022). Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions. IEEE S&P 2022, pp. 754-768. DOI 10.1109/SP46214.2022.9833571.
2. Perry, N., Srivastava, M., Kumar, D., Boneh, D. (2023). Do Users Write More Insecure Code with AI Assistants? ACM CCS 2023, pp. 2785-2799. DOI 10.1145/3576915.3623157.
3. Ullah, S., Han, M., Pujar, S., Pearce, H., Coskun, A., Stringhini, G. (2024). LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?). IEEE S&P 2024, pp. 862-880. DOI 10.1109/SP54263.2024.00210.
4. Ding, Y., Fu, Y., Ibrahim, O., Sitawarin, C., Chen, X., Alomair, B., Wagner, D., Ray, B., Chen, Y. (2025). Vulnerability Detection with Code Language Models: How Far Are We? ICSE 2025, pp. 1729-1741. DOI 10.1109/ICSE55347.2025.00038.
5. Johnson, B., Song, Y., Murphy-Hill, E., Bowdidge, R. (2013). Why Don't Software Developers Use Static Analysis Tools to Find Bugs? ICSE 2013, pp. 672-681. DOI 10.1109/ICSE.2013.6606613.
6. Le Goues, C., Pradel, M., Roychoudhury, A. (2019). Automated Program Repair. Communications of the ACM 62(12), pp. 56-65. DOI 10.1145/3318162.
7. Pearce, H., Tan, B., Ahmad, B., Karri, R., Dolan-Gavitt, B. (2023). Examining Zero-Shot Vulnerability Repair with Large Language Models. IEEE S&P 2023, pp. 2339-2356. DOI 10.1109/SP46215.2023.10179420.
8. Guo, C., Pleiss, G., Sun, Y., Weinberger, K. Q. (2017). On Calibration of Modern Neural Networks. ICML 2017, PMLR 70:1321-1330 (no DOI).
9. Microsoft Foundry: Microsoft-Decision-1 catalog entry and the 9 October 2026 Foundry Blog post (links in `PHYLAX_RELATED_WORK.md` section 2.7); Bandit README (PyPI and GitHub).

**Partly verified** (confirm on the publisher's page): Chess and McGraw (2004), *Static Analysis for Security*, IEEE Security & Privacy 2(6), pp. 76-79 (DOI not checked); Greshake et al. (2023), indirect prompt injection, AISec 2023, arXiv:2302.12173 (DOI only on a secondary index).

**Not yet verified:** the table in `PHYLAX_RELATED_WORK.md` section 3 (Rice 1953; Cousot and Cousot 1977; Livshits and Lam 2005; Yamaguchi et al. 2014; Sadowski et al. 2018; the learned-detector papers; the LLM-and-static-analysis hybrids IRIS and LLift; repair papers including GenProg and Qi et al.; Parasuraman et al. 2000; Wilson 1927; and others). The Microsoft Learn usage page could not be fetched in this audit; read it directly.

## 13. Where to find things

| You need | Look in |
|---|---|
| the exact decision rules | `security_service/core/policy.py`; `PHYLAX_ALGORITHM_GUIDE.md` section 5 |
| how findings merge | `security_service/core/scan_service.py` (`_same_issue`, `_combine`) |
| the model's questions and wording | `security_service/core/questions.py` |
| the original rules | `security_service/adapters/js_rules.py` (`RULES`); the table in the algorithm guide |
| the correction prompt and edit rules | `security_service/adapters/foundry_corrector.py`, `core/patching.py` |
| the verification checks | `security_service/core/verification.py` |
| the evaluation gate and records | `benchmark/classifier_eval.py` (`GATE`); `benchmark/results/` |
| the HTTP contract | `openapi.yaml` |
| what was planned versus built | `PHYLAX_PROJECT_OVERVIEW.md` section 10 |

## 13b. What changed on 2026-11-11 (read before citing anything above)

Contract 1.4.0 added a secrets-only lane for configuration and text files (`coverage.limited_scope`). Its held-out run is recorded in `benchmark/results/config_heldout_verdict.md`; the numbers in
`PHYLAX_EVALUATION.md` section 4.x are the ones to cite, with the caveat there. A behavior-level fix-quality harness exists (`benchmark/fix_eval.py`); it has not been run on the real model, so
"Astra's fixes keep behavior" is still unmeasured. Ask the team for the report file it writes (`benchmark/results/fix_eval_<date>.md`) and for the JavaScript Decision-1 verdict when they exist.

## 14. Claims to avoid

"Phylax detects X% of vulnerabilities." "The decision model is more accurate than static analysis." "Phylax's corrections are correct." "Phylax is robust to prompt injection." "Phylax secures AI-generated code." "The approach is novel" (until the literature search is done). "The model works on JavaScript." Each is either unmeasured or contradicted by a recorded limitation.
