*PHYLAX · RELATED WORK*

# Where Phylax sits in the literature.

This document has three jobs: explain the algorithmic approaches behind Phylax and say honestly which ones Phylax implements; survey the research around it; and list what the literature does not settle. It is written so that the paper's author can tell, for every claim and every reference, how far to trust it.

## 0. How to read the verification labels

References were checked by web search on **2026-11-11**.

| Label | Meaning |
|---|---|
| **VERIFIED** | an authoritative page (publisher, arXiv, a proceedings or index record) was found that confirmed the authors, title, venue and the identifier given |
| **PARTLY VERIFIED** | the bibliographic details were confirmed, but not the DOI, or the DOI only through a secondary index. Confirm on the publisher's page |
| **NOT YET VERIFIED** | from memory. **Do not cite until checked.** These are candidates to search for, not references |

No result in this document is attributed to a paper unless the paper was found and the result appeared in its abstract or text. Where a number comes from a snippet of a paper's own abstract, the label says so. **The paper's author should still read each verified paper before relying on it**: a search result confirms that a paper exists and what it claims, not that it supports every use a review makes of it.

## 1. Algorithmic background and comparison

For each technique: what it is, its foundation, how it works, input and output, computational character where established, advantages, limitations, why it matters to Phylax, and **whether Phylax implements it or only uses a related idea**. Statements about computational complexity are given only where they follow from the design or the repository; general complexity results are flagged as background to verify.

### 1.1 Rule-based static analysis

- **Foundation.** Program analysis built on parsing: source text becomes a syntax tree and rules examine it. Whether a program has a given semantic property (such as "this input can reach this command") is undecidable in general, which is the content of Rice's theorem (*background; reference not yet verified*). Practical tools therefore approximate, and the research framework for doing so soundly is abstract interpretation (*background; not yet verified*).
- **How it works.** Parse; walk the tree; at each node a rule checks a structural pattern; a match produces a finding with a category, a location, a severity and a confidence.
- **Input and output.** Source text in; findings out.
- **Computational character.** Parsing and one pass of rule matching are linear in the size of the tree times the number of rules, in the design used here. The cost of deeper analyses (interprocedural data flow, symbolic execution) grows with the analysis and is not established by this repository.
- **Advantages.** Deterministic, explainable (a rule, a line, a weakness identifier), fast, cheap, local, testable one rule at a time. Developer studies find that trust depends on false-positive rates and on how warnings are presented (Johnson et al., 2013, verified).
- **Limitations.** Limited to written patterns; look-alikes produce false positives and disguised code produces false negatives; shallow reach across functions and files.
- **Relevance.** It is the only evidence that can **block** in Phylax, because it is the only evidence a person can check.
- **Implemented in Phylax?** **Yes**: abstract-syntax-tree pattern matching (Bandit for Python; original rules on tree-sitter for JavaScript and TypeScript). **Implemented in a limited form**: input tracking one assignment deep and string-operation propagation, which resembles taint analysis within one function. **Not implemented**: interprocedural taint, abstract interpretation, symbolic execution, or code property graphs.

### 1.2 AI and LLM-based vulnerability detection

- **Foundation.** Statistical learning on code. Three families: (a) models trained on code representations (token sequences, graphs) to classify functions as vulnerable or not; (b) pre-trained code language models fine-tuned for that task; (c) prompting a general generative model to find or explain vulnerabilities.
- **How it works.** Family (a) and (b): train on labelled functions, predict a label or score. Family (c): put code in a prompt, parse the answer.
- **Input and output.** Code in; a label, a probability, or text out.
- **Computational character.** Inference cost scales with tokens and model size; training costs are a one-off for (a) and (b). Not benchmarked here beyond Phylax's measured latency and price (algorithm guide, section 8).
- **Advantages.** Can generalise beyond fixed patterns and see across a whole file or function; fast to prototype.
- **Limitations, with evidence.** Evaluations of general LLMs on vulnerability detection report high false-positive rates, non-deterministic answers, incorrect or unfaithful reasoning, and brittleness to simple code augmentations such as renaming (Ullah et al., 2024, verified). Evaluations on realistic data report that earlier benchmark results are heavily inflated by poor labels and leakage: a model scoring 68.26% F1 on one benchmark scored 3.09% F1 on a more realistic one (Ding et al., 2025, verified). Text inside code can steer a model (see Greshake et al., 2023, section 2.8).
- **Relevance.** Phylax uses a learned model, but constrained, for exactly the reasons above.
- **Implemented in Phylax?** **A related idea, not a standard implementation.** Phylax calls a *decision model* with a fixed list of yes/no questions and reads probabilities (family (c)'s zero-shot use, but with typed numeric outputs instead of free text). Phylax **does not train or fine-tune** any model. A generative detector exists in the code but is **not in the pipeline and was never compared with a real model**.

### 1.3 Hybrid security-analysis architectures

- **Foundation.** Combining evidence from independent analyses. Three patterns: *late fusion* of independent detectors' outputs; *model-assisted static analysis*, where a model supplies what a rule engine cannot (for example, which functions are sources and sinks) and the analysis does the reasoning; *model triage*, where a model filters a static analyser's alerts. (The latter two correspond to published work listed as **not yet verified** in section 3: IRIS, and the LLift line.)
- **How Phylax combines.** Late fusion with an **asymmetric trust rule** and a **corroboration** step: engine outputs are merged when two independent engines report the same issue, a model can join but never outrank a rule, and only rule-backed findings of high severity and confidence can block.
- **Input and output.** Several finding lists in; one finding list and a verdict out.
- **Advantages.** Each engine's weakness is covered by another's strength; a model's miscalibration cannot cause a block; the evidence tier tells a reviewer how much weight a finding deserves.
- **Limitations.** Late fusion does not let the model improve the rules' reasoning; corroboration needs both engines to agree on category and line; the benefit depends on the engines' errors being independent, which was not tested.
- **Implemented in Phylax?** **Yes** for late fusion with corroboration. **No** for model-assisted analysis or model triage.

### 1.4 Confidence-based classification

- **Foundation.** A classifier outputs a score; a decision rule compares it with a threshold. If the score is a *calibrated* probability (a prediction of 0.8 is right about 80% of the time), the threshold has a direct meaning. Modern neural networks are often poorly calibrated, and simple post-hoc methods such as temperature scaling can fix much of it (Guo et al., 2017, verified). Calibration is commonly measured by expected calibration error. Allowing a classifier to abstain or hand off to a human when it is unsure is a related idea; Microsoft's guidance for the model Phylax uses recommends treating a low top probability as a signal to hand over.
- **How Phylax does it.** A category whose probability reaches **0.70** becomes a finding. 0.70 was validated by a pre-registered held-out test and is tied to one model version.
- **Advantages.** Simple, auditable, and the threshold is an explicit, versioned decision.
- **Limitations.** Phylax does **not** calibrate the probabilities and did not measure calibration error; the threshold was chosen against 14 vulnerable and 25 safe cases, so it is imprecise; a different model version may need a different threshold.
- **Implemented in Phylax?** **Thresholding: yes. Calibration: no** (a research direction).

### 1.5 Risk-based decision policies

- **Foundation.** Decision under uncertainty: choose the action with the least expected harm given costs of errors. Practical systems often use ordinal rules instead (a risk matrix of severity against likelihood). Fail-safe defaults (deny on doubt) are a long-standing secure-design principle (*background; the usual reference is not yet verified*).
- **How Phylax does it.** Two ordinal thresholds on severity and confidence, plus **fail-closed coverage rules**: a skipped source file or a failed engine can never yield a PASS. A PASS is defined as "nothing found by the checks that ran", never as "safe".
- **Advantages.** Explainable and testable; the asymmetry between a false PASS and a false alarm is built into the rules.
- **Limitations.** No explicit costs, no per-category thresholds, no learning of the policy; thresholds are authors' judgements.
- **Implemented in Phylax?** **A rule-based ordinal policy: yes.** Expected-cost minimisation or any learned policy: **no** (a research direction).

### 1.6 Automated code repair

- **Foundation.** Program repair searches for a modification that makes a program meet a specification. Families: generate-and-validate search, semantic (constraint-based) repair, learning-based repair, and, more recently, repair by large language models. A recognised challenge is **weak specifications** and the resulting **overfitting**: a patch that satisfies the available check without being correct (Le Goues, Pradel and Roychoudhury, 2019, verified, discusses this and lists patching security vulnerabilities as a use case).
- **LLM repair evidence.** Pearce et al. (2023, verified) study zero-shot vulnerability repair with commercial and open models: the models together repaired all synthetic and hand-crafted scenarios, but a qualitative look at real historical examples showed difficulty producing functionally correct code.
- **How Phylax does it.** A model proposes **whole-line edits** that are applied strictly (each must match exactly once, edits must not overlap, any mismatch refuses the whole proposal), then a diff is produced and verified.
- **Advantages.** Constrained output makes scope checkable and output cheap; every proposal passes the same checks regardless of author.
- **Limitations.** The validation oracle is a *static* one (the same engines no longer find the problem; the file parses; no undefined names for Python); there is no test-based oracle, so overfitting to the scanner is possible: a patch can satisfy the scanner while changing behaviour. Success rate is unmeasured.
- **Implemented in Phylax?** **Yes**, as constrained LLM generate-and-validate. Search-based, semantic and learned repair are **not** implemented.

### 1.7 Verification and re-scan

- **Foundation.** Regression and differential analysis: after a change, re-run the analysis and compare. The distinction between a patch that is *plausible* (passes the check) and one that is *correct* is central to the repair literature (*the classic reference on this, Qi et al., 2015, is not yet verified*).
- **How Phylax does it.** Four checks (scope, syntax with an undefined-name test for Python, patch size, re-scan of the changed files with the same engines, counted per file and category because line numbers shift), with three outcomes (passed, failed, inconclusive); only "passed" makes a fix applicable. The same checks run on a correction the caller wrote.
- **Advantages.** Cheap, deterministic, catches the failure modes seen in practice (a removed import, a patch that touches the wrong file, a "fix" that leaves the problem).
- **Limitations.** Does not run tests or the program; the undefined-name check is not done for JavaScript and TypeScript; a model-only new finding is listed but does not fail the check.
- **Implemented in Phylax?** **Yes.**

### 1.8 Human approval

- **Foundation.** The human-factors literature on levels of automation (*Parasuraman, Sheridan and Wickens, 2000: not yet verified*) distinguishes systems that suggest from systems that act. Phylax sits at "suggest, and act only after approval". The user-study evidence that people over-trust AI assistants (Perry et al., 2023, verified) is a reason a gate must be *designed*, not merely allowed.
- **Implemented in Phylax?** **Yes**: per-file approval; no mechanism to skip it.

## 2. Verified references

Each entry gives the full citation, what it contributes, the models or algorithms involved, its limitations, and its connection to Phylax. "Connection" says whether the work relates to a method Phylax **implements** or is **background**.

### 2.1 Security of AI-generated code (motivation)

**[P22] Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., Karri, R. (2022). *Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions.* 2022 IEEE Symposium on Security and Privacy (SP), pp. 754-768. DOI 10.1109/SP46214.2022.9833571.** arXiv:2108.09293. A revised version appeared in *Communications of the ACM* 68(2), 2025, pp. 96-105, DOI 10.1145/3610721. **VERIFIED.**
- Contribution: a systematic study of how often GitHub Copilot suggests insecure code, using scenarios built around high-risk weakness types from MITRE's list; 89 scenarios, 1,689 programs, of which about 40% were found vulnerable.
- Method: automatic and manual analysis of generated completions across diversity of weaknesses, prompts and domains.
- Limitations: one tool at one point in time; handcrafted scenarios. A later paper describes it as covering "a small set of synthetic prompts" with limited insight into realistic settings with human developers (Perry et al., verified text).
- Connection: **motivation** (why independent review of AI-written code). Not a method Phylax implements.

**[P23] Perry, N., Srivastava, M., Kumar, D., Boneh, D. (2023). *Do Users Write More Insecure Code with AI Assistants?* Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS '23), pp. 2785-2799. DOI 10.1145/3576915.3623157.** arXiv:2211.03622. **VERIFIED.**
- Contribution: a user study of how people interact with an AI code assistant on security-related tasks. Participants with access to the assistant wrote insecure solutions more often on four of five tasks and were more likely to believe their code was secure; participants who trusted the assistant less and engaged more with their prompts produced fewer vulnerabilities.
- Method: a controlled study with an assistant based on an OpenAI code model (codex-davinci-002); statistical modelling per task.
- Limitations: a finite set of tasks and one assistant generation; results may not carry over to current agents.
- Connection: **motivation** for a human gate and for independence. Background, not an implemented method.

### 2.2 LLMs as vulnerability detectors, and how to evaluate them

**[U24] Ullah, S., Han, M., Pujar, S., Pearce, H., Coskun, A., Stringhini, G. (2024). *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks.* 2024 IEEE Symposium on Security and Privacy (SP), pp. 862-880. DOI 10.1109/SP54263.2024.00210.** arXiv:2312.12575. **VERIFIED.**
- Contribution: SecLLMHolmes, an automated framework with 228 code scenarios (eight vulnerability types, in C and Python) for testing LLMs along eight dimensions; applied to eight LLMs.
- Findings (from its abstract): performance varies by model and prompting technique, but all models show a high false-positive rate and flag patched code as still vulnerable; outputs are non-deterministic; reasoning is often wrong even when the verdict is right; chain-of-thought reasoning can be confused by simple code changes; the models fail on real-world projects.
- Limitations: C and Python only; models of that period.
- Connection: the strongest published argument for Phylax's design: a decision model with fixed questions instead of free-text reasoning, and **no model-only blocking**. Background for the design, and a source of evaluation dimensions (determinism, robustness to augmentation) that Phylax has **not** yet measured.

**[D25] Ding, Y., Fu, Y., Ibrahim, O., Sitawarin, C., Chen, X., Alomair, B., Wagner, D., Ray, B., Chen, Y. (2025). *Vulnerability Detection with Code Language Models: How Far Are We?* 47th IEEE/ACM International Conference on Software Engineering (ICSE 2025), pp. 1729-1741. DOI 10.1109/ICSE55347.2025.00038.** arXiv:2403.18624. **VERIFIED.**
- Contribution: shows that existing vulnerability datasets have poor label accuracy, high duplication and leakage (up to 18.9% of test samples leaked from training in some benchmarks); introduces **PrimeVul** (6,968 vulnerable and 228,800 benign functions across 140 weakness types), a chronological split, a metric designed for practical use (VD-S), and a **pair-wise evaluation** (can the detector tell a vulnerable function from its fixed counterpart?). A state-of-the-art 7-billion-parameter model fell from 68.26% F1 on an older benchmark to 3.09% on PrimeVul; larger models were not better in the strictest settings. It argues that plain accuracy is inappropriate because of the base-rate problem (vulnerabilities are rare).
- Limitations: function-level data and a focus on code language models; check the paper for the languages its dataset covers before generalising to JavaScript or TypeScript.
- Connection: **methodology** most relevant to Phylax's evaluation: the paired vulnerable/fixed/look-alike design, held-out discipline, and the point that author-written benchmarks and balanced sets overstate real performance. Background, not an implemented method.

### 2.3 Static analysis in practice, and the human factor

**[J13] Johnson, B., Song, Y., Murphy-Hill, E., Bowdidge, R. (2013). *Why Don't Software Developers Use Static Analysis Tools to Find Bugs?* Proceedings of the 35th International Conference on Software Engineering (ICSE 2013), pp. 672-681. DOI 10.1109/ICSE.2013.6606613.** **VERIFIED.**
- Contribution: interviews with 20 developers; all felt use is beneficial, but false positives and the way warnings are presented are among the barriers. It points to the need for interactive mechanisms to help fix defects.
- Limitations: qualitative, 20 participants, tools of that time.
- Connection: supports Phylax's separation of severity and confidence, its explanations, and its offer of corrections. **Background.**

**[CM04] Chess, B., McGraw, G. (2004). *Static Analysis for Security.* IEEE Security & Privacy 2(6), pp. 76-79.** **PARTLY VERIFIED**: the title, authors, venue, volume, issue, pages and year were confirmed from another paper's reference list; the DOI was not checked.
- Connection: a short, widely cited introduction to security-oriented static analysis. **Background.** Read it before citing it.

### 2.4 Automated repair

**[LG19] Le Goues, C., Pradel, M., Roychoudhury, A. (2019). *Automated Program Repair.* Communications of the ACM 62(12), pp. 56-65. DOI 10.1145/3318162.** **VERIFIED.**
- Contribution: an overview of automated program repair for a general audience: techniques (including genetic programming, symbolic execution, learning), use cases (including patching security vulnerabilities), and the central challenge of **weak specifications** and **overfitting**.
- Limitations: a viewpoint article from 2019, before LLM-based repair.
- Connection: the framing for Phylax's correction and verification stages (a patch passing a check is not the same as a correct patch). **Background.**

**[P23b] Pearce, H., Tan, B., Ahmad, B., Karri, R., Dolan-Gavitt, B. (2023). *Examining Zero-Shot Vulnerability Repair with Large Language Models.* 2023 IEEE Symposium on Security and Privacy (SP), pp. 2339-2356. DOI 10.1109/SP46215.2023.10179420.** arXiv:2112.02125. **VERIFIED.**
- Contribution: a large-scale study of five commercial black-box models, an open-source model and a locally trained model on synthetic, hand-crafted and real-world security bugs, for zero-shot repair.
- Finding (from its abstract): collectively the models repaired all synthetic and hand-crafted scenarios, but a qualitative evaluation on real historical examples showed challenges in generating functionally correct code. It also studies how hard it is to phrase prompts well.
- Limitations: models of 2021 to 2022; check the paper for the languages of its scenarios before generalising.
- Connection: closest published work to Phylax's use of Astra; supports requiring **verification and human approval** because proposals can be wrong in ways a quick check misses. Related to, not the same as, Phylax's constrained edit approach.

### 2.5 Probabilities and calibration

**[G17] Guo, C., Pleiss, G., Sun, Y., Weinberger, K. Q. (2017). *On Calibration of Modern Neural Networks.* Proceedings of the 34th International Conference on Machine Learning (ICML 2017), PMLR 70:1321-1330.** arXiv:1706.04599. No DOI was found for this one. **VERIFIED.**
- Contribution: shows modern neural networks are poorly calibrated; defines expected calibration error and reliability diagrams; finds that temperature scaling, a single-parameter variant of Platt scaling, is surprisingly effective.
- Connection: the theory for why a threshold on a probability is meaningful only if the probability is calibrated, which Phylax has **not** verified for Decision-1. **Background and a research direction.**

### 2.6 Prompt injection

**[GR23] Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., Fritz, M. (2023). *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* Proceedings of the ACM Workshop on Artificial Intelligence and Security (AISec 2023).** arXiv:2302.12173. **PARTLY VERIFIED**: authors, title and arXiv record confirmed; the venue (AISec 2023) and the DOI 10.1145/3605764.3623985 were found only on a secondary literature index. Confirm both on the ACM page.
- Contribution: introduces **indirect prompt injection**, where instructions are placed in data an application retrieves, blurring the line between data and instructions; a security taxonomy of resulting threats; demonstrations on real systems and synthetic applications.
- Connection: code under review is exactly such data. It motivates Phylax's injection test (comments claiming a security review, or telling reviewers to ignore instructions), the random per-request tag names around code in the correction prompt, and the rule that no model decides alone. **Related, not implemented as a defence**: Phylax reduces the risk and says so.

### 2.7 Official documentation for the components

- **Microsoft-Decision-1.** Microsoft Foundry model catalog entry: https://ai.azure.com/catalog/models/Microsoft-Decision-1 (verified in search: describes a decision-scoring model that returns calibrated probability scores for fixed answer options instead of generated text, and states it is not designed or evaluated as the sole automated decision-maker in consequential decisions about people). Microsoft Foundry Blog, "Introducing Microsoft-Decision-1 in Microsoft Foundry for decision and classification workloads", 9 October 2026: https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/introducing-microsoft-decision-1-in-microsoft-foundry-for-decision-and-classific/4562742 (verified). Microsoft Learn usage guide, "Deploy and use Microsoft-Decision-1 in Microsoft Foundry": https://learn.microsoft.com/en-us/azure/foundry/foundry-models/how-to/use-foundry-models-microsoft-decision (its existence and role were confirmed from several citing pages; **the page itself could not be fetched in this audit**, so the paper's author should read it directly for the exact request format, the three question types, limitations, and the model-version policy). The repository's adapter records that it was checked against this page on 2026-10-09 and confirmed by a real call on 2026-10-23. The claims that the model is post-trained from Qwen3.5-9B, has a context of about 33,000 tokens and is priced per input token come from **secondary sources** that cite Microsoft's pages; confirm them in the catalog before use.
- **Bandit.** README on PyPI and GitHub (verified in search): "a tool designed to find common security issues in Python code", which "processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes"; tests are executed as the node visitor visits each node; test IDs such as B102 `exec_used`; `-l` and `-i` select severity and confidence levels. Project: https://github.com/PyCQA/bandit.
- **tree-sitter, CWE, OWASP, NIST SARD / Juliet:** official documentation exists and is relevant (the parser library used for the JavaScript rules; the weakness catalogue Phylax's findings cite; common benchmark and test-suite resources) but **was not re-fetched in this audit**. Cite from the official sites after reading them.

## 3. Candidates not yet verified

**Do not cite any of these until it has been looked up.** The details are from memory and may contain errors. They are listed because a review of this area would be expected to engage with them.

| Topic | Candidate (author, short title, venue, year as remembered) | Why it matters to Phylax |
|---|---|---|
| Undecidability of program properties | Rice, "Classes of recursively enumerable sets and their decision problems", Trans. AMS, 1953 | why static analysis must approximate |
| Abstract interpretation | Cousot and Cousot, "Abstract interpretation: a unified lattice model...", POPL, 1977 | the soundness-oriented framework |
| Security static analysis | Livshits and Lam, "Finding security vulnerabilities in Java applications with static analysis", USENIX Security, 2005 | taint analysis for injection flaws |
| Code property graphs | Yamaguchi et al., "Modeling and discovering vulnerabilities with code property graphs", IEEE S&P, 2014 | graph representation for vulnerability queries |
| Industrial static analysis | Sadowski et al., "Lessons from building static analysis tools at Google", CACM, 2018 | false-positive tolerance, workflow integration |
| Learning-based detection | Russell et al., deep representation learning for vulnerability detection, ICMLA, 2018; Zhou et al., "Devign", NeurIPS, 2019; Li et al., "VulDeePecker", NDSS, 2018; Fu and Tantithamthavorn, "LineVul", MSR, 2022 | the learned-detector family |
| Critique of learned detection | Chakraborty et al., "Deep learning based vulnerability detection: are we there yet?", IEEE TSE, 2022 | evaluation realism (complements Ding et al.) |
| Survey | Ghaffarian and Shahriari, vulnerability analysis with machine learning and data mining, ACM Computing Surveys, 2017 | an overview of learned detection |
| LLMs for vulnerabilities | Thapa et al., "Transformer-based language models for software vulnerability detection", ACSAC, 2022; Steenhoek et al., a study of LLM capabilities for vulnerability detection, 2024; Zhou et al., a literature review on LLMs for vulnerability detection and repair | the LLM-detection family |
| Hybrid static and LLM | Li et al., "LLM-assisted static analysis for detecting security vulnerabilities" (IRIS), ICLR, 2025; Li et al., "The Hitchhiker's guide to program analysis: a journey with large language models" (LLift) | model-assisted analysis and triage (**not** what Phylax does) |
| AI-generated code | Sandoval et al., "Lost at C: a user study on the security implications of LLM code assistants", USENIX Security, 2023; He and Vechev, "Large language models for code: security hardening and adversarial testing", CCS, 2023 | more motivation; hardening |
| Program repair | Le Goues et al., "GenProg", IEEE TSE, 2012; Monperrus, "Automatic software repair: a bibliography", ACM Computing Surveys, 2018; Qi et al., patch plausibility and correctness, ISSTA, 2015; Xia and Zhang, "Automated program repair in the era of large pre-trained language models", ICSE, 2023; Fu et al., "VulRepair", ESEC/FSE, 2022 | repair, overfitting, learned repair |
| Human-automation | Parasuraman, Sheridan and Wickens, "A model for types and levels of human interaction with automation", IEEE Trans. SMC-A, 2000; Horvitz, "Principles of mixed-initiative user interfaces", CHI, 1999 | the approval gate |
| Calibration and uncertainty | Kadavath et al., "Language models (mostly) know what they know", 2022; Platt, probabilistic outputs for support vector machines, 1999 | calibration of model confidence |
| Statistics | Wilson, "Probable inference, the law of succession, and statistical inference", JASA, 1927 | the interval used in the evaluation document |
| Secure design principle | Saltzer and Schroeder, "The protection of information in computer systems", Proc. IEEE, 1975 | fail-safe defaults |

## 4. Research gaps

These are gaps **relative to what this audit found**. The audit's searches were targeted at verifying specific references, not a systematic literature review, so the author must search before claiming that something is unstudied.

1. **Decision models with typed probabilities as vulnerability classifiers.** Phylax uses a model that outputs probabilities for a fixed set of questions instead of generating text. No published evaluation of this design for vulnerability detection was found in this audit; whether this approach avoids the reported weaknesses of free-text LLM reasoning is an open empirical question, and Phylax's own evidence (a 39-case held-out set) is far too small to answer it.
2. **Asymmetric-trust hybrids.** Phylax lets rules block and models only request review. The policy is simple, but there is no published comparison of such a policy against alternatives (for example, calibrated joint scoring) on the same data.
3. **Coverage-aware verdicts.** Phylax defines PASS as "nothing found by the checks that ran on the files scanned" and never as "safe", and treats skipped files and failed engines as non-passes. How such explicit coverage semantics affect developer trust and behaviour is not studied here.
4. **Static verification of model-generated patches.** The re-scan oracle is cheap, but its false-confidence rate is unknown: how often does a patch that satisfies the scanner still break behaviour or leave the weakness reachable another way? Phylax has not measured it.
5. **Robustness to prompt injection in code review models.** The evaluation shows a single injected sentence lowering catches at higher thresholds. Systematic evaluation of injection against decision models, and defences beyond tag randomisation, are open.
6. **Threshold stability across model versions.** The model's provider states the underlying model may change under the same name. How stable a validated threshold is, and how to re-validate cheaply, is an engineering and research question.
7. **Realistic, independent benchmarks for agent-written code**, especially in JavaScript and TypeScript, with paired vulnerable and fixed versions and labels by someone other than the tool's author.
8. **Run-to-run determinism** of decision models; not measured here.
9. **Human approval design.** Phylax shows what was checked, the exact diff, and a consent statement. Whether this design reduces rubber-stamping (the over-confidence Perry et al. observed) is untested.
