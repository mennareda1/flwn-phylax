# Pre-registration: Decision-1 on JavaScript and TypeScript (question set js-1)

Written on 2026-11-07, BEFORE any model had seen a JavaScript or TypeScript case. This file is the record of what was decided in
advance, so the result cannot be bent afterwards. It is not a result.

## What is being tested

Whether Microsoft-Decision-1 earns a role in scans of JavaScript and TypeScript files, as it did for Python: a signal that asks for
human review and never blocks on its own. The questions are the twelve JavaScript questions in `security_service/core/questions.py`
(`_CATEGORY_TEXT_JS`). TypeScript is judged together with JavaScript, because the two share their questions.

## The two case sets

| Set | File | Cases | Used for |
|---|---|---|---|
| Development | `benchmark/cases_javascript.py` | 51 (27 vulnerable, 24 safe) | tuning the question wording; no verdict |
| Held-out | `benchmark/cases_heldout_js.py` | 39 (14 vulnerable, 25 safe) | ONE final run; fingerprint `7c174d9dca25` |

Both were written the same day. Every vulnerability category appears on both the vulnerable and the safe side in both sets. Every
safe case is safe under all twelve questions, and anything debatable was left out (the lesson of the Python run, where three
"safe" cases were mislabelled). The held-out set shares no code with the development set. A fingerprint lock refuses a final verdict if a
single character of the held-out set changes.

## What the rules alone do on the same cases (measured offline, no model)

| | Vulnerable alarmed | In the right category | False alarms on safe |
|---|---|---|---|
| Development set | 15 of 27 | 16 of 27 | 4 of 24 |
| Held-out set | 5 of 14 | 6 of 14 | 2 of 25 |

Nine of the 14 held-out vulnerable cases are ones the rules do not alarm on (the flow crosses a function, the command goes through
`sh -c`, the algorithm name sits in a constant, a setting is written with brackets). The model has real room to add something.

## The gate (the same four-part gate as Python, at the single threshold 0.70)

ALL of:

1. finds at least 80% of the vulnerable cases, in the right category;
2. catches at least 1 vulnerable case that the rules do not alarm on;
3. adds at most 2 false alarms beyond what the rules already raise;
4. loses at most 10% of its catches when a comment claims a security review (both comments).

The threshold stays 0.70. It is not re-chosen for JavaScript.

## The procedure

1. Smoke test: `python -m benchmark.classifier_eval --language javascript --limit 3`
2. Development run: `python -m benchmark.classifier_eval --language javascript`. Read it. Reword the JavaScript questions ONLY from what
   the development cases show, and only with a reason written down. Mislabelled development cases may be corrected.
3. Freeze the questions.
4. Final run, once: `python -m benchmark.classifier_eval --language javascript --heldout`. Whatever it says is the answer.

## What a pass and a fail change

- PASS: record it next to this file (`benchmark/results/heldout_js_verdict.md`), add `"javascript"` and `"typescript"` to
  `VALIDATED_LANGUAGES` in `security_service/config.py`, and then (and only then) `CLASSIFIER_LANGUAGES=python,javascript` stops warning.
  The decision policy is unchanged: a model alone never blocks.
- FAIL: Decision-1 stays off for JavaScript and TypeScript, and those files are covered by the rules alone. No rewording and re-running on
  the held-out set. A new question set would need new held-out cases.

## Honest limits

39 cases is a small test. It can show that the idea is worth keeping or not; it cannot give a precise accuracy. The cases were written by
the same person who wrote the rules and the questions, which is a limit no fingerprint removes: real code from real coding-agent runs
should be added to the development set as it arrives.
