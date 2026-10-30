"""
security_service/core/scan_service.py

ScanService: the core entry point behind POST /v1/scans.

    report = ScanService().scan([SourceFile("app.py", code)], language="python")
    report = ScanService().scan_snippet(code, "python")      # one-file convenience

Pipeline: prepare files (limits, language, skips) -> run each engine on each file -> tag
findings with their file -> merge rule and model findings that agree -> assign ids -> decide
-> build the report with coverage and provenance. Submitted code is never executed.
Engine failures become SCAN_FAILED, never a silent PASS.
"""

from __future__ import annotations

import time
from dataclasses import replace

from security_service.adapters.bandit import BanditAnalyzer
from security_service.adapters.classifier_detector import ClassifierDetector
from security_service.adapters.secrets_check import SecretsAnalyzer
from security_service.core.policy import decide, decide_nothing_scanned
from security_service.core.files import (
    InvalidScanInput,
    Limits,
    PayloadTooLarge,
    SourceFile,
    UnsupportedLanguage,
    prepare_files,
)
from security_service.core.schema import (
    Confidence,
    Coverage,
    Decision,
    Engine,
    EvidenceTier,
    Finding,
    Provenance,
    ScanReport,
    Severity,
    SkippedFile,
    highest_severity,
    severity_counts,
)
from security_service.ports.analyzer import Analyzer, AnalyzerResult
from security_service.version import CONTRACT_VERSION, POLICY_VERSION, SERVICE_VERSION

__all__ = ["ScanService", "InvalidScanInput", "PayloadTooLarge", "UnsupportedLanguage", "SourceFile", "merge_corroborated"]


def _rule_backed(finding: Finding) -> bool:
    return finding.evidence_tier in (EvidenceTier.STATIC_RULE, EvidenceTier.CORROBORATED)


def _same_issue(a: Finding, b: Finding) -> bool:
    if a.vulnerability_type != b.vulnerability_type:
        return False
    if set(a.sources) & set(b.sources):
        return False            # one engine reporting twice is not corroboration
    if a.line is None or b.line is None:
        # A decision model describes the whole file, so it has no line. It may join a rule finding of the same type
        # in the same file (merging runs per file), and only that: two whole-file findings do not merge, and a rule
        # finding without a line is never absorbed.
        whole, other = (a, b) if a.line is None else (b, a)
        if other.line is None or _rule_backed(whole) or not _rule_backed(other):
            return False
        return whole.severity.rank <= other.severity.rank
    if abs(a.line - b.line) > 1:
        return False
    if _rule_backed(a) and _rule_backed(b):
        return True             # two independent rule engines agree
    if _rule_backed(a) or _rule_backed(b):
        rule, model = (a, b) if _rule_backed(a) else (b, a)
        # A model that claims MORE than the rule does stands on its own, so its concern is not
        # silently absorbed; and it can never lift a rule finding's severity through a merge.
        return model.severity.rank <= rule.severity.rank
    return False                # two model findings are not corroboration


def _combine(a: Finding, b: Finding) -> Finding:
    rules = [f for f in (a, b) if _rule_backed(f)]
    base = max(rules, key=lambda f: f.severity.rank)     # severity and confidence come from rules only
    other = b if base is a else a
    base.sources = base.sources + [source for source in other.sources if source not in base.sources]
    base.evidence_tier = EvidenceTier.CORROBORATED
    if _rule_backed(other):
        if other.confidence.rank > base.confidence.rank:
            base.confidence = other.confidence
        base.cwe = base.cwe or other.cwe
    return base


def merge_corroborated(findings: list[Finding]) -> list[Finding]:
    """Fold findings that two independent engines report for the same issue (same type, same or
    adjacent line) into one CORROBORATED finding listing both sources. Call it per file.

    Rule engines agreeing merge. A rule and a model merge only when the model claims no more than
    the rule, and the merged finding keeps the rule's severity and confidence. Two models never
    merge, and one engine's repeated findings never merge."""
    merged: list[Finding] = []
    for finding in findings:
        for index, existing in enumerate(merged):
            if _same_issue(existing, finding):
                merged[index] = _combine(existing, finding)
                break
        else:
            merged.append(finding)
    return merged


def _skipped_note(skipped: list[SkippedFile]) -> tuple[str, ...]:
    if not skipped:
        return ()
    shown = ", ".join(f"{s.path} ({s.reason})" for s in skipped[:5])
    more = f" and {len(skipped) - 5} more" if len(skipped) > 5 else ""
    return (f"Not scanned: {shown}{more}.",)


class ScanService:
    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
        strict_coverage: bool = True,
        limits: Limits | None = None,
    ):
        self._analyzers: list[Analyzer] = analyzers if analyzers is not None else [BanditAnalyzer(), SecretsAnalyzer()]
        # True: if any analyzer fails and nothing else was found, the result is SCAN_FAILED
        # (a PASS needs full coverage). False: a PASS may stand when an analyzer such as the
        # LLM is down, with the reduced coverage stated.
        self._strict_coverage = strict_coverage
        self._limits = limits or Limits()

    @classmethod
    def from_settings(cls, settings, classifier=None, **kwargs) -> "ScanService":
        """The service as configured: rules and the secrets check always, plus Decision-1 when CLASSIFIER_ENABLED is on.
        If it is on but Decision-1 is not configured, this raises at once: failing loudly at startup beats quietly
        running without the engine someone believes is protecting them. `classifier` lets tests supply a stand-in."""
        analyzers = [BanditAnalyzer(), SecretsAnalyzer()]
        if settings.classifier_enabled:
            if classifier is None:
                problems = settings.problems()
                if problems:
                    raise ValueError("CLASSIFIER_ENABLED is on but Decision-1 is not ready: " + "; ".join(problems))
                from security_service.adapters.decision1 import Decision1Classifier
                classifier = Decision1Classifier.from_settings(settings)
            analyzers.append(ClassifierDetector(classifier, settings.classifier_threshold, settings.classifier_required))
        return cls(analyzers, limits=settings.limits(), **kwargs)

    @property
    def supported_languages(self) -> frozenset[str]:
        return frozenset(lang for a in self._analyzers for lang in a.languages)

    @property
    def limits(self) -> Limits:
        return self._limits

    def capabilities(self, retention_hours: int = 24, max_wait_seconds: int = 30) -> dict:
        """The body of GET /v1/capabilities: what this deployment supports right now."""
        roles: dict[str, set[str]] = {}
        for analyzer in self._analyzers:
            for language in analyzer.languages:
                roles.setdefault(language, set()).add(analyzer.role)
        return {
            "contract_version": CONTRACT_VERSION,
            "service_version": SERVICE_VERSION,
            "policy_version": POLICY_VERSION,
            "languages": [{"id": lang, "roles": sorted(r)} for lang, r in sorted(roles.items())],
            "limits": {
                "max_files": self._limits.max_files,
                "max_file_bytes": self._limits.max_file_bytes,
                "max_total_bytes": self._limits.max_total_bytes,
                "max_wait_seconds": max_wait_seconds,
            },
            "retention_hours": retention_hours,
        }

    def scan_snippet(self, code: str, language: str = "python", path: str = "snippet") -> ScanReport:
        return self.scan([SourceFile(path, code)], language=language)

    def scan(self, files: list[SourceFile], language: str | None = None, context: dict | None = None) -> ScanReport:
        """`context` carries optional caller hints (framework, untrusted inputs). Accepted so adding
        hint support later is not a contract change; the current engines ignore it."""
        started = time.monotonic()
        prepared, skipped = prepare_files(files, language, self.supported_languages, self._limits)
        skipped_blocking = sum(1 for s in skipped if s.blocks_pass)
        notes = _skipped_note(skipped)

        findings: list[Finding] = []
        analyzers_ok: set[str] = set()
        analyzers_failed: dict[str, str] = {}      # every failure, for the coverage statement
        required_failed: dict[str, str] = {}       # failures that make a pass impossible (strict coverage)
        optional_failed: dict[str, str] = {}       # an optional engine (the classifier) being down does not
        engines_used: list[Analyzer] = []

        for file in prepared:
            file_findings: list[Finding] = []
            for analyzer in self._analyzers:
                if file.language not in analyzer.languages:
                    continue
                if analyzer not in engines_used:
                    engines_used.append(analyzer)
                result: AnalyzerResult = analyzer.analyze(file.content, file.language)
                if result.ok:
                    analyzers_ok.add(result.analyzer)
                    for finding in result.findings:
                        finding.path = file.path
                    file_findings.extend(result.findings)
                else:
                    key, error = f"{result.analyzer}@{file.path}", result.error or "unknown error"
                    analyzers_failed[key] = error
                    (required_failed if getattr(analyzer, "required", True) else optional_failed)[key] = error
            findings.extend(merge_corroborated(file_findings))

        if optional_failed:
            engines = sorted({key.split("@", 1)[0] for key in optional_failed})
            first = next(iter(optional_failed.values()))[:140]
            notes = notes + (f"Optional engine {', '.join(engines)} was unavailable for {len(optional_failed)} file(s) ({first}); "
                             "those files were judged by the other engines only.",)

        findings.sort(key=lambda f: (f.path or "", f.line or 0, f.rule_id or ""))
        for index, finding in enumerate(findings, start=1):
            finding.id = f"f{index}"

        if prepared:
            outcome = decide(findings, sorted(analyzers_ok), required_failed,
                             self._strict_coverage, skipped_blocking, notes)
        else:
            outcome = decide_nothing_scanned(skipped_blocking, notes)

        return ScanReport(
            status="failed" if outcome.decision == Decision.SCAN_FAILED else "completed",
            decision=outcome.decision,
            risk_level=highest_severity(findings),
            findings=findings,
            summary=severity_counts(findings),
            decision_reasons=list(outcome.reasons),
            coverage=Coverage(
                languages=sorted({f.language for f in prepared}),
                files_scanned=[f.path for f in prepared],
                skipped_files=skipped,
                analyzers_run=sorted(analyzers_ok),
                analyzers_failed=analyzers_failed,
            ),
            provenance=Provenance(
                CONTRACT_VERSION, SERVICE_VERSION, POLICY_VERSION,
                [Engine(a.role, a.name) for a in engines_used],
            ),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class _StubAnalyzer:
    """Test double so demo() needs no real tools."""

    role = "analyzer"
    languages = ("python",)

    def __init__(self, name: str, findings: list[Finding] | None = None, error: str | None = None,
                 fail_on: str | None = None):
        self.name = name
        self._findings = findings or []
        self._error = error
        self._fail_on = fail_on     # only fail when the code contains this text

    def analyze(self, code: str, language: str) -> AnalyzerResult:
        error = self._error
        if self._fail_on is not None and self._fail_on not in code:
            error = None
        elif self._fail_on is not None:
            error = f"cannot analyze {self._fail_on}"
        findings = [replace(f, sources=list(f.sources)) for f in self._findings]   # independent copies per call
        return AnalyzerResult(analyzer=self.name, findings=findings if error is None else [], error=error)


def demo() -> None:
    """Dependency-free self-check of validation and orchestration (stub engines, no Bandit)."""
    import json

    def finding(vtype="command_injection", sev=Severity.HIGH, conf=Confidence.HIGH,
                tier=EvidenceTier.STATIC_RULE, line=2, src="stub"):
        return Finding(vtype, sev, conf, tier, [src], "S1", None, line, "x", "d", "r")

    service = ScanService([_StubAnalyzer("stub")])

    # request-level validation raises the right classes
    for bad in ([], [SourceFile("a.py", None)]):
        try:
            service.scan(bad)
            raise AssertionError("expected InvalidScanInput")
        except InvalidScanInput:
            pass
    try:
        service.scan([SourceFile("a.cob", "x")], language="cobol")
        raise AssertionError("expected UnsupportedLanguage")
    except UnsupportedLanguage:
        pass

    # clean single file: PASS with an explicit coverage statement and provenance
    report = service.scan_snippet("x = 1")
    assert report.decision == Decision.PASS and report.status == "completed"
    assert report.coverage.files_scanned == ["snippet"] and report.coverage.languages == ["python"]
    assert report.coverage.not_assessable
    assert report.provenance.engines[0].role == "analyzer" and report.provenance.contract_version == CONTRACT_VERSION

    # multi-file: findings are tagged with their file, sorted, and get sequential ids
    two = ScanService([_StubAnalyzer("stub", [finding(line=5), finding(line=1)])])
    report = two.scan([SourceFile("b.py", "x = 1"), SourceFile("a.py", "y = 2")])
    assert [(f.path, f.line, f.id) for f in report.findings] == [
        ("a.py", 1, "f1"), ("a.py", 5, "f2"), ("b.py", 1, "f3"), ("b.py", 5, "f4")]
    assert report.decision == Decision.BLOCK and report.summary["high"] == 4

    # a rule and a model reporting the same issue become ONE corroborated finding (per file)
    both = ScanService([_StubAnalyzer("rules", [finding(line=2, src="rules")]),
                        _StubAnalyzer("model", [finding(tier=EvidenceTier.MODEL_SUSPICION, conf=Confidence.LOW,
                                                        sev=Severity.MEDIUM, line=3, src="fake-model")])])
    merged = both.scan([SourceFile("a.py", "x"), SourceFile("b.py", "y")])
    assert len(merged.findings) == 2     # one per file, each corroborated, not four
    assert all(f.evidence_tier == EvidenceTier.CORROBORATED and f.sources == ["rules", "fake-model"] for f in merged.findings)

    # rule engines agreeing merge into ONE corroborated finding that keeps the higher severity;
    # one engine reporting twice does not merge
    twice = ScanService([_StubAnalyzer("bandit", [finding(vtype="hardcoded_credentials", sev=Severity.LOW, conf=Confidence.MEDIUM, line=3, src="bandit")]),
                         _StubAnalyzer("secrets", [finding(vtype="hardcoded_credentials", sev=Severity.MEDIUM, conf=Confidence.MEDIUM, line=3, src="secrets")])])
    agreed = twice.scan_snippet("x")
    assert len(agreed.findings) == 1 and agreed.findings[0].severity == Severity.MEDIUM
    assert agreed.findings[0].evidence_tier == EvidenceTier.CORROBORATED and sorted(agreed.findings[0].sources) == ["bandit", "secrets"]
    assert agreed.decision == Decision.REVIEW_REQUIRED                       # LOW alone would have passed
    dup = ScanService([_StubAnalyzer("bandit", [finding(line=2, src="bandit"), finding(line=2, src="bandit")])])
    assert len(dup.scan_snippet("x").findings) == 2

    # a model can never lift a rule finding's severity or confidence through a merge...
    low_rule = finding(sev=Severity.LOW, conf=Confidence.LOW, src="rules", line=4)
    hot_model = finding(tier=EvidenceTier.MODEL_SUSPICION, sev=Severity.CRITICAL, conf=Confidence.HIGH, line=4, src="fake-model")
    assert [f.evidence_tier for f in merge_corroborated([low_rule, hot_model])] == [EvidenceTier.STATIC_RULE, EvidenceTier.MODEL_SUSPICION]
    unmerged = ScanService([_StubAnalyzer("rules", [low_rule]), _StubAnalyzer("model", [hot_model])]).scan_snippet("x")
    assert len(unmerged.findings) == 2 and unmerged.decision == Decision.REVIEW_REQUIRED   # its concern stands, but it cannot block
    mild_model = finding(tier=EvidenceTier.MODEL_SUSPICION, sev=Severity.LOW, conf=Confidence.HIGH, line=4, src="fake-model")
    kept = merge_corroborated([finding(sev=Severity.MEDIUM, conf=Confidence.LOW, src="rules", line=4), mild_model])
    assert len(kept) == 1 and kept[0].severity == Severity.MEDIUM and kept[0].confidence == Confidence.LOW   # the model did not raise confidence

    # two models never merge into a "corroborated" (rule-backed) finding
    two_models = merge_corroborated([finding(tier=EvidenceTier.MODEL_SUSPICION, src="m1", line=2), finding(tier=EvidenceTier.MODEL_SUSPICION, src="m2", line=2)])
    assert len(two_models) == 2 and all(f.evidence_tier == EvidenceTier.MODEL_SUSPICION for f in two_models)

    # a model-only finding never blocks
    lone = ScanService([_StubAnalyzer("model", [finding(tier=EvidenceTier.MODEL_SUSPICION, sev=Severity.CRITICAL, vtype="ssrf")])])
    assert lone.scan_snippet("x").decision == Decision.REVIEW_REQUIRED

    # skipped files: source files block a pass; docs do not; both are listed in coverage
    partial = service.scan([SourceFile("ok.py", "x = 1"), SourceFile("app.js", "let a = 1"), SourceFile("README.md", "# hi")])
    assert partial.decision == Decision.REVIEW_REQUIRED
    assert {s.path: s.blocks_pass for s in partial.coverage.skipped_files} == {"app.js": True, "README.md": False}
    assert any("Not scanned" in r for r in partial.decision_reasons)
    docs_only = service.scan([SourceFile("README.md", "# hi"), SourceFile("notes.txt", "hello")])
    assert docs_only.decision == Decision.PASS and docs_only.coverage.files_scanned == []
    assert "nothing was checked" in docs_only.decision_reasons[0]
    js_only = service.scan([SourceFile("app.js", "let a = 1")])
    assert js_only.decision == Decision.REVIEW_REQUIRED and js_only.status == "completed"

    # one file fails analysis -> a would-be PASS becomes SCAN_FAILED (fail closed), naming the file
    flaky = ScanService([_StubAnalyzer("stub", fail_on="BROKEN")])
    failed = flaky.scan([SourceFile("good.py", "x = 1"), SourceFile("bad.py", "BROKEN")])
    assert failed.decision == Decision.SCAN_FAILED and failed.status == "failed"
    assert list(failed.coverage.analyzers_failed) == ["stub@bad.py"]
    assert ScanService([_StubAnalyzer("stub", error="boom")]).scan_snippet("x = 1").decision == Decision.SCAN_FAILED
    assert ScanService([]).scan_snippet("x = 1", language=None).decision in (Decision.PASS, Decision.REVIEW_REQUIRED, Decision.SCAN_FAILED)

    # relaxed coverage
    optional = [_StubAnalyzer("rules"), _StubAnalyzer("model", error="timeout")]
    assert ScanService(optional).scan_snippet("x = 1").decision == Decision.SCAN_FAILED
    relaxed = ScanService(optional, strict_coverage=False).scan_snippet("x = 1")
    assert relaxed.decision == Decision.PASS and "model@snippet" in relaxed.coverage.analyzers_failed

    # ---- Decision-1 as an engine (a scripted stand-in: no network)
    from security_service.adapters.fakes import FakeClassifier
    from security_service.config import Settings
    from security_service.ports.classifier import Answer, ClassifierUnavailable, StateTooLarge

    def model(levels, default=0.02, required=False):
        scripted = FakeClassifier(lambda state, q: Answer("yes_no", probability=levels.get(q.id, default)), name="scripted-model")
        return ClassifierDetector(scripted, required=required)

    # a model alone can ask for review, but never blocks, even at 100% on every category
    loud = ScanService([_StubAnalyzer("rules"), model({}, default=1.0)]).scan_snippet("x = 1")
    assert loud.decision == Decision.REVIEW_REQUIRED and len(loud.findings) == 12
    assert all(f.evidence_tier == EvidenceTier.MODEL_SUSPICION and f.line is None for f in loud.findings)
    assert any("rest on model suspicion alone" in r for r in loud.decision_reasons)
    assert [e.role for e in loud.provenance.engines] == ["analyzer", "classifier"] and "scripted-model" in loud.coverage.analyzers_run
    assert ScanService([_StubAnalyzer("rules"), model({})]).scan_snippet("x = 1").decision == Decision.PASS     # quiet rules, quiet model

    # the model agrees with a rule about the same problem in the same file: ONE corroborated finding, with the rule's severity and line
    rule_hit = finding(vtype="path_traversal", sev=Severity.MEDIUM, conf=Confidence.HIGH, line=4, src="rules")
    both = ScanService([_StubAnalyzer("rules", [rule_hit]), model({"path_traversal": 0.97})]).scan_snippet("x")
    only = both.findings[0]
    assert len(both.findings) == 1 and only.evidence_tier == EvidenceTier.CORROBORATED and only.line == 4 and only.severity == Severity.MEDIUM
    assert sorted(only.sources) == ["rules", "scripted-model"]
    # ... but a model that claims MORE than the rule (a LOW rule finding) stands on its own, beside it
    weak_rule = finding(vtype="path_traversal", sev=Severity.LOW, conf=Confidence.LOW, line=4, src="rules")
    beside = ScanService([_StubAnalyzer("rules", [weak_rule]), model({"path_traversal": 0.97})]).scan_snippet("x")
    assert len(beside.findings) == 2 and beside.decision == Decision.REVIEW_REQUIRED
    # ... and a rule-backed HIGH still blocks, with the model folded into the same finding
    blocked = ScanService([_StubAnalyzer("rules", [finding(line=2, src="rules")]), model({"command_injection": 0.99})]).scan_snippet("x")
    assert blocked.decision == Decision.BLOCK and len(blocked.findings) == 1

    # whole-file findings never merge with each other, and a lineless rule finding is never absorbed by a model
    whole = lambda src: Finding("ssrf", Severity.MEDIUM, Confidence.LOW, EvidenceTier.MODEL_SUSPICION, [src], "MODEL-ssrf", None, None, "e", "d", "r")
    assert len(merge_corroborated([whole("m1"), whole("m2")])) == 2
    lineless_rule = Finding("ssrf", Severity.HIGH, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["rules"], "R", None, None, "e", "d", "r")
    assert len(merge_corroborated([lineless_rule, whole("m1")])) == 2

    # an OPTIONAL engine being down does not stop a pass; the gap is stated in the coverage and in the reasons
    class Broken:
        role, name, max_state_tokens = "classifier", "down-model", 30_000

        def __init__(self, error):
            self.error = error

        def classify(self, state, questions):
            raise self.error

    outage = ClassifierUnavailable("unavailable after 3 attempts (last: HTTP 503)")
    optional = ScanService([_StubAnalyzer("rules"), ClassifierDetector(Broken(outage))]).scan_snippet("x = 1")
    assert optional.decision == Decision.PASS and optional.status == "completed"
    assert "down-model@snippet" in optional.coverage.analyzers_failed and "down-model" not in optional.coverage.analyzers_run
    assert any("Optional engine down-model" in r and "other engines only" in r for r in optional.decision_reasons)
    # ... a REQUIRED one makes the same outage fatal to a pass; a failed RULES engine is fatal either way
    assert ScanService([_StubAnalyzer("rules"), ClassifierDetector(Broken(outage), required=True)]).scan_snippet("x = 1").decision == Decision.SCAN_FAILED
    assert ScanService([_StubAnalyzer("rules", error="boom"), model({})]).scan_snippet("x = 1").decision == Decision.SCAN_FAILED
    # ... and a file too big for the model is a noted gap, not a failed scan
    too_big = ScanService([_StubAnalyzer("rules"), ClassifierDetector(Broken(StateTooLarge("code is too large for one question")))]).scan_snippet("x = 1")
    assert too_big.decision == Decision.PASS and any("StateTooLarge" in e for e in too_big.coverage.analyzers_failed.values())
    # the outage never hides a real finding: rules still BLOCK
    assert ScanService([_StubAnalyzer("rules", [finding(src="rules")]), ClassifierDetector(Broken(outage))]).scan_snippet("x").decision == Decision.BLOCK

    # built from settings: off by default; on adds exactly the model engine with the configured threshold and strictness
    assert [a.name for a in ScanService.from_settings(Settings.from_env({}))._analyzers] == ["bandit", "secrets"]
    on_env = {"CLASSIFIER_ENABLED": "true", "CLASSIFIER_THRESHOLD": "0.8", "CLASSIFIER_REQUIRED": "true",
              "FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com", "FOUNDRY_API_KEY": "k" * 32, "SCAN_MAX_FILES": "7"}
    stand_in = FakeClassifier(lambda state, q: Answer("yes_no", probability=0.01), name="stand-in")
    configured = ScanService.from_settings(Settings.from_env(on_env), classifier=stand_in)
    detector = configured._analyzers[-1]
    assert [a.name for a in configured._analyzers] == ["bandit", "secrets", "stand-in"] and detector.threshold == 0.8 and detector.required is True
    assert configured.limits.max_files == 7
    assert {"id": "python", "roles": ["analyzer", "classifier"]} in configured.capabilities()["languages"]
    try:                                          # on but not configured: fail loudly at startup, never run quietly without it
        ScanService.from_settings(Settings.from_env({"CLASSIFIER_ENABLED": "true"}))
        raise AssertionError("expected a refusal")
    except ValueError as refusal:
        assert "not ready" in str(refusal)

    # capabilities reflect the configured engines
    caps = ScanService([_StubAnalyzer("stub")]).capabilities()
    assert caps["languages"] == [{"id": "python", "roles": ["analyzer"]}] and caps["limits"]["max_files"] == 50

    # CRLF input keeps line numbers aligned; report is JSON-serializable
    crlf = two.scan([SourceFile("a.py", "a\r\nb\r\nc")])
    payload = json.loads(json.dumps(crlf.to_dict()))
    assert payload["decision"] == "block" and payload["findings"][0]["path"] == "a.py"
    assert set(payload) == {"status", "decision", "risk_level", "findings", "summary", "decision_reasons",
                            "coverage", "provenance", "duration_ms"}

    print("core.scan_service OK: multi-file scan, skips, corroboration, fail-closed paths, JSON report")


if __name__ == "__main__":
    demo()
