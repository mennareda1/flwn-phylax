"""
security_service/adapters/classifier_detector.py

Turns a decision model's answers into scan findings, so the scan service can use Decision-1 as one more engine.

For each Python file it asks the 12 security questions (core/questions.py) in ONE request. Every category whose
probability reaches the threshold becomes a finding.

What those findings are, and are not (the policy is in core/policy.py and does not change):
  - They are MODEL SUSPICION: evidence_tier model_suspicion, severity medium. A model gives a probability, not a
    severity, so one flat level is the honest choice. The policy sends a model-only finding to human review and
    never lets it block: a model alone never blocks.
  - They describe the WHOLE FILE: line is null. A decision model says "this file probably has this problem", it does
    not point at a line. When a rule already found the same problem in the file, the scan service folds the two
    into one corroborated finding instead of reporting it twice.
  - Confidence is capped at medium, even at 99%: the model's probability is not evidence a person can check.
  - They contain no code: the evidence line is a sentence about the assessment, never a quote of the file.
  - Code is masked before it leaves (the Decision-1 adapter does it), so the model sees <REDACTED_SECRET> markers.

The threshold defaults to 0.70, the value the held-out test (2026-10-23) validated. The engine is OPTIONAL by default
(`required=False`): if the model is unreachable, the scan still finishes on the rules and the report says so. Set
`required=True` to make a model outage fail the scan instead.

Limits that are not hidden: a file larger than the model accepts in one request (about 30,000 tokens) is not assessed
by the model, because chunking is not built yet; the rules still scan it, and the report records the model's failure.
"""

from __future__ import annotations

import time

from security_service.core.questions import CATEGORY_IDS, RECOMMENDATIONS_JS, build_questions, question_family
from security_service.core.schema import RECOMMENDATIONS, Confidence, EvidenceTier, Finding, Severity
from security_service.ports.analyzer import AnalyzerResult
from security_service.ports.classifier import ClassifierError

DEFAULT_THRESHOLD = 0.70
_WORDING = {family: {q.id: q.options["true"] for q in build_questions(language=family)} for family in ("python", "javascript")}     # what "yes" means, per category


class ClassifierDetector:
    role = "classifier"

    def __init__(self, classifier, threshold: float = DEFAULT_THRESHOLD, required: bool = False, languages: tuple[str, ...] = ("python",)):
        """`languages` are the languages the model is asked about. JavaScript and TypeScript are added only once the model has passed the held-out
        test for them (benchmark/cases_heldout_js.py); until then a JavaScript file is covered by the rules alone."""
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be above 0 and at most 1")
        unknown = [lang for lang in languages if question_family(lang) not in ("python", "javascript")]
        if unknown or not languages:
            raise ValueError(f"no questions are written for language {unknown[0]!r}" if unknown else "the classifier needs at least one language")
        expanded = list(languages)
        if any(question_family(lang) == "javascript" for lang in languages):
            for sibling in ("javascript", "typescript"):                # they share their questions and were judged together: enabling one covers both
                if sibling not in expanded:
                    expanded.append(sibling)
        self.languages = tuple(expanded)
        self._classifier = classifier
        self.name = classifier.name
        self.threshold = threshold
        self.required = required
        self._questions = {family: build_questions(language=family) for family in {question_family(lang) for lang in self.languages}}

    def analyze(self, code: str, language: str) -> AnalyzerResult:
        started = time.monotonic()
        if language not in self.languages:
            return AnalyzerResult(analyzer=self.name, error=f"the classifier does not support language {language!r}")
        try:
            family = question_family(language)
            result = self._classifier.classify(code, self._questions[family])
        except ClassifierError as problem:        # unavailable, rejected, or too large: reported, never raised into the scan
            return AnalyzerResult(analyzer=self.name, error=f"{type(problem).__name__}: {problem}")

        findings = []
        for category in CATEGORY_IDS:
            probability = result.answers[category].probability
            if probability < self.threshold:
                continue
            findings.append(Finding(
                vulnerability_type=category,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM if probability >= 0.9 else Confidence.LOW,
                evidence_tier=EvidenceTier.MODEL_SUSPICION,
                sources=[self.name],
                rule_id=f"MODEL-{category}",
                cwe=None,
                line=None,
                evidence=f"Whole-file assessment by {self.name}: {probability:.0%} likely. No single line is identified.",
                description=f"The decision model rates this file {probability:.0%} likely to have this problem: {_WORDING[family][category]}",
                recommendation=(RECOMMENDATIONS_JS if family == "javascript" else RECOMMENDATIONS)[category],
            ))
        return AnalyzerResult(analyzer=self.name, findings=findings, duration_ms=int((time.monotonic() - started) * 1000),
                              stats={"model": result.model, "input_tokens": result.input_tokens})


def demo() -> None:
    from security_service.adapters.fakes import FakeClassifier
    from security_service.ports.classifier import Answer, ClassifierUnavailable, StateTooLarge

    secret_code = 'DB_PASSWORD = "SuperSecret123!"\nopen(name)\n'

    def scripted(levels: dict[str, float], default: float = 0.02):
        return FakeClassifier(lambda state, q: Answer("yes_no", probability=levels.get(q.id, default)), name="scripted-decision")

    # a category at or above the threshold becomes exactly one finding; below it, nothing (the boundary is exact)
    detector = ClassifierDetector(scripted({"path_traversal": 0.70, "ssrf": 0.6999, "sql_injection": 0.95}))
    result = detector.analyze(secret_code, "python")
    assert result.ok and sorted(f.vulnerability_type for f in result.findings) == ["path_traversal", "sql_injection"]
    by_type = {f.vulnerability_type: f for f in result.findings}
    assert by_type["path_traversal"].confidence == Confidence.LOW and by_type["sql_injection"].confidence == Confidence.MEDIUM
    assert result.stats["model"] == "fake-1.0.0"

    # what every finding says about itself: model suspicion, flat medium severity, whole file, rule id, no code, never high confidence
    for finding in result.findings:
        assert finding.evidence_tier == EvidenceTier.MODEL_SUSPICION and finding.severity == Severity.MEDIUM
        assert finding.line is None and finding.cwe is None and finding.sources == ["scripted-decision"]
        assert finding.rule_id == f"MODEL-{finding.vulnerability_type}" and finding.recommendation
        assert finding.confidence != Confidence.HIGH
        rendered = str(finding.to_dict())
        assert "SuperSecret123" not in rendered and "open(name)" not in rendered and "DB_PASSWORD" not in rendered, "the finding quotes the code"
    assert "path" in by_type["path_traversal"].description.lower() and "70%" in by_type["path_traversal"].description

    # a clean file gives nothing; a model that says yes to everything gives one finding per category, never more
    assert ClassifierDetector(scripted({})).analyze("x = 1\n", "python").findings == []
    assert len(ClassifierDetector(scripted({}, default=0.99)).analyze("x = 1\n", "python").findings) == len(CATEGORY_IDS) == 12

    # the threshold is respected, and validated
    assert [f.vulnerability_type for f in ClassifierDetector(scripted({"ssrf": 0.85}), threshold=0.9).analyze("x", "python").findings] == []
    assert len(ClassifierDetector(scripted({"ssrf": 0.85}), threshold=0.8).analyze("x", "python").findings) == 1
    for bad in (0.0, -0.1, 1.5):
        try:
            ClassifierDetector(scripted({}), threshold=bad)
            raise AssertionError(f"threshold {bad} must be rejected")
        except ValueError:
            pass

    # failures are reported as a failed engine, never raised into the scan, and carry no code
    class Failing:
        role, name, max_state_tokens = "classifier", "failing-decision", 30_000

        def __init__(self, error):
            self.error = error

        def classify(self, state, questions):
            raise self.error

    for error in (ClassifierUnavailable("unavailable after 3 attempts (last: HTTP 503)"), StateTooLarge("code is too large for one question")):
        failed = ClassifierDetector(Failing(error)).analyze(secret_code, "python")
        assert not failed.ok and failed.findings == [] and type(error).__name__ in failed.error and "SuperSecret123" not in failed.error
    assert not ClassifierDetector(scripted({})).analyze("let a = 1", "javascript").ok

    # optional unless asked otherwise
    assert ClassifierDetector(scripted({})).required is False and ClassifierDetector(scripted({}), required=True).required is True
    assert ClassifierDetector(scripted({})).role == "classifier"

    # JavaScript and TypeScript: only when the detector was built for them, with their own questions, wording and advice
    asked = []

    def spy(levels):
        def answer(state, q):
            asked.append(q)
            return Answer("yes_no", probability=levels.get(q.id, 0.02))
        return FakeClassifier(answer, name="spy-decision")

    python_only = ClassifierDetector(spy({}))
    refused = python_only.analyze("let a = 1", "javascript")
    assert not refused.ok and "does not support language 'javascript'" in refused.error and asked == []         # not asked until the model has passed its test for JavaScript
    web = ClassifierDetector(spy({"command_injection": 0.95, "ssrf": 0.72}), languages=("python", "javascript", "typescript"))
    for language in ("javascript", "typescript"):
        asked.clear()
        found = web.analyze("const { exec } = require('child_process');\n", language)
        assert found.ok and sorted(f.vulnerability_type for f in found.findings) == ["command_injection", "ssrf"], language
        assert len(asked) == 12 and "child_process.exec" in next(q.instructions for q in asked if q.id == "command_injection") and not any("os.system" in q.instructions for q in asked)
        by_kind = {f.vulnerability_type: f for f in found.findings}
        assert "execFile" in by_kind["command_injection"].recommendation and "subprocess" not in by_kind["command_injection"].recommendation
        assert "child_process" in by_kind["command_injection"].description or "built from changing text" in by_kind["command_injection"].description
        assert by_kind["command_injection"].evidence_tier.value == "model_suspicion" and by_kind["command_injection"].line is None      # whole-file, never a line, never a rule
    asked.clear()
    py = web.analyze("import os\n", "python")                                                            # the same detector still asks Python its own questions
    assert py.ok and any("os.system" in q.instructions for q in asked) and all("child_process" not in q.instructions for q in asked)
    by_py = {f.vulnerability_type: f for f in py.findings}
    assert "shell=True" in by_py["command_injection"].recommendation and "execFile" not in by_py["command_injection"].recommendation       # Python keeps Python's advice
    for bad in ((), ("cobol",), ("python", "cobol")):
        try:
            ClassifierDetector(spy({}), languages=bad)
            raise AssertionError(f"languages {bad!r} must be refused")
        except ValueError:
            pass
    assert ClassifierDetector(spy({})).languages == ("python",) and web.languages == ("python", "javascript", "typescript")
    assert ClassifierDetector(spy({}), languages=("javascript",)).languages == ("javascript", "typescript")                  # either one covers both
    assert ClassifierDetector(spy({}), languages=("python", "typescript")).languages == ("python", "typescript", "javascript")

    print("adapters.classifier_detector OK: threshold boundary exact, findings are whole-file model suspicion with no code and never high confidence, failures reported not raised")


if __name__ == "__main__":
    demo()
