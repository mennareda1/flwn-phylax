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
from security_service.adapters.js_rules import JsRulesAnalyzer, available as js_available
from security_service.adapters.secrets_check import SecretsAnalyzer
from security_service.core.policy import decide, decide_nothing_scanned
from security_service.core.files import (
    InvalidScanInput,
    Limits,
    PayloadTooLarge,
    SECRETS_ONLY_LANGUAGES,
    SourceFile,
    UnsupportedLanguage,
    prepare_files,
    sha256_text,
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


def default_analyzers() -> list:
    """The always-on engines: Bandit for Python, the secrets check, and our JavaScript and TypeScript rules when their parser packages are
    installed. In CODE the secrets check covers a language only if a rules engine covers it too, so a code file never counts as scanned on secrets alone. Configuration and text
    files (SECRETS_ONLY_LANGUAGES) are the one deliberate exception: the secrets check is their only engine, and every report says so (coverage.limited_scope)."""
    languages = ("python", "javascript", "typescript") if js_available() else ("python",)
    analyzers: list = [BanditAnalyzer(), SecretsAnalyzer(languages, config_languages=tuple(sorted(SECRETS_ONLY_LANGUAGES)))]
    if js_available():
        analyzers.append(JsRulesAnalyzer())
    return analyzers


class ScanService:
    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
        strict_coverage: bool = True,
        limits: Limits | None = None,
    ):
        self._analyzers: list[Analyzer] = analyzers if analyzers is not None else default_analyzers()
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
        analyzers = default_analyzers()
        if settings.classifier_enabled:
            if classifier is None:
                problems = settings.problems()
                if problems:
                    raise ValueError("CLASSIFIER_ENABLED is on but Decision-1 is not ready: " + "; ".join(problems))
                from security_service.adapters.decision1 import Decision1Classifier
                classifier = Decision1Classifier.from_settings(settings)
            analyzers.append(ClassifierDetector(classifier, settings.classifier_threshold, settings.classifier_required, settings.classifier_languages))
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
            "languages": [{"id": lang, "roles": sorted(r), "scope": "secrets_only" if lang in SECRETS_ONLY_LANGUAGES else "full"} for lang, r in sorted(roles.items())],
            "limits": {
                "max_files": self._limits.max_files,
                "max_file_bytes": self._limits.max_file_bytes,
                "max_total_bytes": self._limits.max_total_bytes,
                "max_wait_seconds": max_wait_seconds,
            },
            "retention_hours": retention_hours,
        }

    def validate_request(self, files: list[SourceFile], language: str | None = None) -> None:
        """Raise exactly the errors scan() would raise for a bad request, without scanning. The HTTP service calls it
        before queuing work, so a bad request is answered at once instead of becoming a failed job."""
        prepare_files(files, language, self.supported_languages, self._limits)

    def scan_snippet(self, code: str, language: str = "python", path: str = "snippet") -> ScanReport:
        return self.scan([SourceFile(path, code)], language=language)

    def scan(self, files: list[SourceFile], language: str | None = None, context: dict | None = None) -> ScanReport:
        """`context` carries optional caller hints (framework, untrusted inputs). Accepted so adding
        hint support later is not a contract change; the current engines ignore it."""
        started = time.monotonic()
        prepared, skipped = prepare_files(files, language, self.supported_languages, self._limits)
        skipped_blocking = sum(1 for s in skipped if s.blocks_pass)
        notes = _skipped_note(skipped)
        limited = [{"path": f.path, "language": f.language, "checked_for": "hardcoded secrets only"} for f in prepared if f.language in SECRETS_ONLY_LANGUAGES]
        if limited:                                  # a configuration file is checked for secrets and nothing else: the verdict must not read as more than that
            shown = ", ".join(item["path"] for item in limited[:5]) + (f" and {len(limited) - 5} more" if len(limited) > 5 else "")
            notes = notes + (f"{len(limited)} configuration or text file(s) were checked for hardcoded secrets only ({shown}).",)

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
                try:
                    result: AnalyzerResult = analyzer.analyze(file.content, file.language)
                except Exception as problem:        # noqa: BLE001 - an engine must RETURN its failures; one that raises fails closed instead
                    # the type only, never the message: an exception message can contain the code being scanned
                    result = AnalyzerResult(analyzer=analyzer.name, error=f"the engine crashed ({type(problem).__name__})")
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
                scanned_files=[{"path": f.path, "sha256": f.sha256} for f in prepared],
                skipped_files=skipped,
                analyzers_run=sorted(analyzers_ok),
                analyzers_failed=analyzers_failed,
                limited_scope=limited,
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
    assert report.coverage.scanned_files == [{"path": "snippet", "sha256": sha256_text("x = 1")}]
    # the report names exactly what was scanned: the hash is of the text AS SUBMITTED, so a file with Windows line endings hashes as it sits on disk
    crlf = service.scan([SourceFile("w.py", "x = 1\r\ny = 2\r\n"), SourceFile("l.py", "x = 1\ny = 2\n")])
    assert crlf.coverage.scanned_files == [{"path": "w.py", "sha256": sha256_text("x = 1\r\ny = 2\r\n")}, {"path": "l.py", "sha256": sha256_text("x = 1\ny = 2\n")}]
    assert crlf.coverage.scanned_files[0]["sha256"] != crlf.coverage.scanned_files[1]["sha256"]
    assert [f["path"] for f in crlf.coverage.scanned_files] == crlf.coverage.files_scanned                                 # the two lists always agree
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

    # an engine that RAISES (instead of returning its failure) fails closed, and its message, which may hold code, never surfaces
    class Raising:
        role, languages, name = "analyzer", ("python",), "raising-engine"

        def analyze(self, code, language):
            raise RuntimeError("boom with the code: " + code[:12])

    survived = ScanService([Raising(), _StubAnalyzer("working", [finding(sev=Severity.MEDIUM, conf=Confidence.MEDIUM, src="working")])]).scan_snippet("x = 1  # TOPSECRET")
    assert survived.decision == Decision.REVIEW_REQUIRED and len(survived.findings) == 1                    # the other engine still counts
    assert survived.coverage.analyzers_failed == {"raising-engine@snippet": "the engine crashed (RuntimeError)"} and "TOPSECRET" not in json.dumps(survived.to_dict()) and "boom" not in json.dumps(survived.to_dict())
    assert ScanService([Raising(), _StubAnalyzer("working")]).scan_snippet("x = 1").decision == Decision.SCAN_FAILED     # a pass is impossible with an engine down
    assert ScanService([Raising()]).scan_snippet("x = 1").decision == Decision.SCAN_FAILED

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
    assert [a.name for a in ScanService.from_settings(Settings.from_env({}))._analyzers] == ["bandit", "secrets", "jsrules"]
    on_env = {"CLASSIFIER_ENABLED": "true", "CLASSIFIER_THRESHOLD": "0.8", "CLASSIFIER_REQUIRED": "true",
              "FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com", "FOUNDRY_API_KEY": "k" * 32, "SCAN_MAX_FILES": "7"}
    stand_in = FakeClassifier(lambda state, q: Answer("yes_no", probability=0.01), name="stand-in")
    configured = ScanService.from_settings(Settings.from_env(on_env), classifier=stand_in)
    detector = configured._analyzers[-1]
    assert [a.name for a in configured._analyzers] == ["bandit", "secrets", "jsrules", "stand-in"] and detector.threshold == 0.8 and detector.required is True
    assert configured.limits.max_files == 7
    assert {"id": "python", "roles": ["analyzer", "classifier"], "scope": "full"} in configured.capabilities()["languages"]
    assert {"id": "javascript", "roles": ["analyzer"], "scope": "full"} in configured.capabilities()["languages"] and detector.languages == ("python",)     # JavaScript is not asked until it has passed its test

    # Decision-1 on JavaScript: only when CLASSIFIER_LANGUAGES says so; then it can flag what the rules cannot see, as a review (never a block)
    sh_c = SourceFile("run.js", "const { spawn } = require('child_process');\nspawn('sh', ['-c', 'convert ' + file + ' out.png']);\n")
    suspicious = FakeClassifier(lambda state, q: Answer("yes_no", probability=0.95 if q.id == "command_injection" else 0.01), name="suspicious")
    off_for_js = ScanService.from_settings(Settings.from_env(on_env), classifier=suspicious).scan([sh_c])
    assert off_for_js.decision == Decision.PASS and off_for_js.findings == []                                                    # the rules cannot see sh -c, and the model is not asked
    on_for_js = ScanService.from_settings(Settings.from_env({**on_env, "CLASSIFIER_LANGUAGES": "python,javascript"}), classifier=suspicious)
    assert {"id": "javascript", "roles": ["analyzer", "classifier"], "scope": "full"} in on_for_js.capabilities()["languages"]
    flagged = on_for_js.scan([sh_c])
    assert flagged.decision == Decision.REVIEW_REQUIRED and [f.vulnerability_type for f in flagged.findings] == ["command_injection"]
    assert flagged.findings[0].evidence_tier.value == "model_suspicion" and "execFile" in flagged.findings[0].recommendation and flagged.findings[0].line is None
    assert "suspicious" in flagged.coverage.analyzers_run and flagged.decision != Decision.BLOCK                                  # a model alone never blocks
    ts_flagged = on_for_js.scan([SourceFile("run.ts", "export const f = (n: string) => n;\n")])                                   # a TypeScript file is asked too
    assert ts_flagged.decision == Decision.REVIEW_REQUIRED and "suspicious" in ts_flagged.coverage.analyzers_run
    try:                                          # on but not configured: fail loudly at startup, never run quietly without it
        ScanService.from_settings(Settings.from_env({"CLASSIFIER_ENABLED": "true"}))
        raise AssertionError("expected a refusal")
    except ValueError as refusal:
        assert "not ready" in str(refusal)

    # validate_request raises what scan raises, and does not scan
    service.validate_request([SourceFile("a.py", "x = 1")])
    for bad_request, error in (([], InvalidScanInput), ([SourceFile("a.cob", "x")], UnsupportedLanguage)):
        try:
            service.validate_request(bad_request, "cobol" if error is UnsupportedLanguage else None)
            raise AssertionError("expected a refusal")
        except error:
            pass

    # fix eligibility is a property of the FINDING, never of the report's decision
    from security_service.core.schema import FixEligibility, SECRET_TYPE, fix_eligibility

    table = {(sev, kind): fix_eligibility(Finding(kind, sev, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["x"], "r", None, 1, "e", "d", "r")).eligible
             for sev in Severity for kind in ("command_injection", SECRET_TYPE)}
    assert table == {(Severity.INFO, "command_injection"): False, (Severity.LOW, "command_injection"): False, (Severity.MEDIUM, "command_injection"): True,
                     (Severity.HIGH, "command_injection"): True, (Severity.CRITICAL, "command_injection"): True,
                     (Severity.INFO, SECRET_TYPE): False, (Severity.LOW, SECRET_TYPE): False, (Severity.MEDIUM, SECRET_TYPE): False,
                     (Severity.HIGH, SECRET_TYPE): False, (Severity.CRITICAL, SECRET_TYPE): False}
    assert "rotate" in fix_eligibility(Finding(SECRET_TYPE, Severity.HIGH, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["x"], "r", None, 1, "e", "d", "r")).reason
    assert isinstance(fix_eligibility(Finding("sql_injection", Severity.MEDIUM, Confidence.LOW, EvidenceTier.MODEL_SUSPICION, ["m"], None, None, None, "", "d", "r")), FixEligibility)
    real_rules = ScanService()
    review_only = real_rules.scan([SourceFile("db.ts", "export const find = (id: string) => pool.query(`SELECT * FROM t WHERE id = ${id}`);\n")])
    assert review_only.decision == Decision.REVIEW_REQUIRED and review_only.findings[0].to_dict()["fix"] == {"eligible": True, "reason": "Medium severity or above: a correction can be offered."}
    quiet_low = real_rules.scan([SourceFile("t.js", "function makeResetToken() {\n  return Math.random().toString(36);\n}\n")])
    assert quiet_low.decision == Decision.PASS and quiet_low.findings and quiet_low.findings[0].severity == Severity.LOW      # a low finding does not even change the decision...
    assert quiet_low.findings[0].to_dict()["fix"]["eligible"] is False and "not corrected by default" in quiet_low.findings[0].to_dict()["fix"]["reason"]
    blocked_with_low = real_rules.scan([SourceFile("a.js", "eval(x);\n"), SourceFile("b.js", "function makeSessionToken() {\n  return Math.random().toString(36);\n}\n")])
    assert blocked_with_low.decision == Decision.BLOCK
    by_rule = {f.rule_id: f.to_dict()["fix"]["eligible"] for f in blocked_with_low.findings}
    assert by_rule == {"JS-EVAL": True, "JS-RANDOM": False}                                                                   # ...and a block does not make a low finding eligible
    leaked_secret = real_rules.scan([SourceFile("c.js", 'const awsKey = "AKIAABCDEFGHIJKLMNOP";\n')])
    assert leaked_secret.findings[0].vulnerability_type == SECRET_TYPE and leaked_secret.findings[0].to_dict()["fix"]["eligible"] is False

    # JavaScript and TypeScript through the default engines: rules, secrets, folder of mixed languages, a broken file, and the capabilities
    real = ScanService()
    vulnerable_js = 'const { exec } = require("child_process");\nexec(`ls ${dir}`);\n'
    js_report = real.scan([SourceFile("app/run.js", vulnerable_js)])
    assert js_report.decision == Decision.BLOCK and js_report.findings[0].rule_id == "JS-EXEC" and js_report.findings[0].path == "app/run.js"
    assert js_report.coverage.languages == ["javascript"] and sorted(js_report.coverage.analyzers_run) == ["jsrules", "secrets"]
    ts_report = real.scan([SourceFile("src/db.ts", "export const find = (id: string) => pool.query(`SELECT * FROM t WHERE id = ${id}`);\n")])
    assert ts_report.decision == Decision.REVIEW_REQUIRED and ts_report.findings[0].rule_id == "JS-SQL" and ts_report.coverage.languages == ["typescript"]
    assert real.scan([SourceFile("ok.js", "const add = (a, b) => a + b;\n")]).decision == Decision.PASS
    leaked = real.scan([SourceFile("cfg.js", 'const awsKey = "AKIAABCDEFGHIJKLMNOP";\nmodule.exports = { awsKey };\n')])      # the secrets check covers JavaScript too
    assert leaked.decision == Decision.REVIEW_REQUIRED and leaked.findings[0].vulnerability_type == "hardcoded_credentials" and "AKIAABCDEFGHIJKLMNOP" not in json.dumps(leaked.to_dict())
    broken_js = real.scan([SourceFile("bad.js", "function ( {")])                                                                      # a file that does not parse is a failed engine: never a pass
    assert broken_js.decision == Decision.SCAN_FAILED and "does not parse" in json.dumps(broken_js.to_dict()["coverage"]["analyzers_failed"])
    mixed = real.scan([SourceFile("a.py", "import os\nos.system(cmd)\n"), SourceFile("b.js", "eval(x);\n"), SourceFile("c.ts", "const n: number = 1;\n"), SourceFile("d.go", "package main\n")])
    assert {f.path for f in mixed.findings} == {"a.py", "b.js"} and mixed.coverage.languages == ["javascript", "python", "typescript"]
    assert [s.path for s in mixed.coverage.skipped_files] == ["d.go"] and mixed.decision == Decision.BLOCK                                # a language with no engine is still skipped, and says so
    assert {"id": "javascript", "roles": ["analyzer"], "scope": "full"} in real.capabilities()["languages"] and {"id": "typescript", "roles": ["analyzer"], "scope": "full"} in real.capabilities()["languages"]
    no_js = ScanService([BanditAnalyzer(), SecretsAnalyzer()])
    skipped_js = no_js.scan([SourceFile("x.js", "eval(y);\n")])                                                                          # without the JavaScript engine, a .js file can never pass
    assert skipped_js.decision == Decision.REVIEW_REQUIRED and skipped_js.coverage.skipped_files[0].reason == "unsupported_language" and skipped_js.coverage.skipped_files[0].blocks_pass

    # capabilities reflect the configured engines
    caps = ScanService([_StubAnalyzer("stub")]).capabilities()
    assert caps["languages"] == [{"id": "python", "roles": ["analyzer"], "scope": "full"}] and caps["limits"]["max_files"] == 50

    # CRLF input keeps line numbers aligned; report is JSON-serializable
    crlf = two.scan([SourceFile("a.py", "a\r\nb\r\nc")])
    payload = json.loads(json.dumps(crlf.to_dict()))
    assert payload["decision"] == "block" and payload["findings"][0]["path"] == "a.py"
    assert set(payload) == {"status", "decision", "risk_level", "findings", "summary", "decision_reasons",
                            "coverage", "provenance", "duration_ms"}

    # configuration and text files: checked for hardcoded secrets ONLY, and the report says so, in a field and in words
    engines = ScanService()
    plain = engines.scan([SourceFile("config/app.yaml", "name: app\nport: 8080\n"), SourceFile("notes.txt", "see the wiki\n")])
    assert plain.decision == Decision.PASS and plain.coverage.files_scanned == ["config/app.yaml", "notes.txt"] and plain.coverage.languages == ["text", "yaml"]
    assert [(i["path"], i["language"], i["checked_for"]) for i in plain.coverage.limited_scope] == [("config/app.yaml", "yaml", "hardcoded secrets only"), ("notes.txt", "text", "hardcoded secrets only")]
    assert any("checked for hardcoded secrets only" in reason for reason in plain.decision_reasons) and "not a guarantee" in " ".join(plain.decision_reasons)
    leaky = engines.scan([SourceFile("config/app.yaml", "db:\n  password: hunter2secret\n")])
    assert leaky.decision == Decision.REVIEW_REQUIRED and [(f.vulnerability_type, f.line, f.rule_id) for f in leaky.findings] == [("hardcoded_credentials", 2, "SECRET-CONFIG")]
    assert "hunter2secret" not in json.dumps(leaky.to_dict()), "an unquoted secret must not appear anywhere in the report"
    known = engines.scan([SourceFile("settings.json", '{"aws": "AKIAIOSFODNN7EXAMPLE"}')])
    assert known.decision == Decision.REVIEW_REQUIRED and known.findings[0].severity == Severity.HIGH and known.findings[0].confidence == Confidence.MEDIUM   # high severity, but a pattern never blocks
    mixed = engines.scan([SourceFile("a.py", "import os\nos.system('ls ' + x)\n"), SourceFile("c.yaml", "p: 1\n")])
    assert mixed.decision == Decision.BLOCK and [i["path"] for i in mixed.coverage.limited_scope] == ["c.yaml"]
    code_only = engines.scan([SourceFile("a.py", "x = 1\n")])
    assert code_only.decision == Decision.PASS and code_only.coverage.limited_scope == [] and not any("hardcoded secrets only" in r for r in code_only.decision_reasons)
    tight = ScanService(default_analyzers(), limits=Limits(max_file_bytes=60))
    big = tight.scan([SourceFile("data.json", '{"a": "' + "x" * 100 + '"}'), SourceFile("layout.xml", "<a/>\n")])
    assert [(sk.path, sk.reason, sk.blocks_pass) for sk in big.coverage.skipped_files] == [("data.json", "file_too_large", False), ("layout.xml", "unsupported_language", False)]
    assert big.decision == Decision.PASS and "nothing was checked" in " ".join(big.decision_reasons)      # listed, never silent; configuration is not source, so it does not block
    assert {"id": "yaml", "roles": ["analyzer"], "scope": "secrets_only"} in engines.capabilities()["languages"] and all(l["scope"] in ("full", "secrets_only") for l in engines.capabilities()["languages"])
    assert {"json", "yaml", "toml", "ini", "properties", "config", "text"} <= engines.supported_languages

    print("core.scan_service OK: multi-file scan, skips, corroboration, fail-closed paths, JSON report, configuration files checked for secrets only and said so")


if __name__ == "__main__":
    demo()
