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

from security_service.adapters.bandit import BanditAnalyzer
from security_service.core.decision import decide, decide_nothing_scanned
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


def merge_corroborated(findings: list[Finding]) -> list[Finding]:
    """Fold a model finding into a rule finding of the same type on the same (or adjacent) line.

    One issue reported by both a rule and a model becomes a single CORROBORATED finding listing
    both sources, instead of two near-duplicate entries. Call it per file.
    """
    static = [f for f in findings if f.evidence_tier == EvidenceTier.STATIC_RULE]
    merged: list[Finding] = []
    for finding in findings:
        if finding.evidence_tier != EvidenceTier.MODEL_SUSPICION:
            merged.append(finding)
            continue
        twin = next(
            (s for s in static
             if s.vulnerability_type == finding.vulnerability_type
             and s.line is not None and finding.line is not None
             and abs(s.line - finding.line) <= 1),
            None,
        )
        if twin is None:
            merged.append(finding)
            continue
        twin.evidence_tier = EvidenceTier.CORROBORATED
        for source in finding.sources:
            if source not in twin.sources:
                twin.sources.append(source)
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
        self._analyzers: list[Analyzer] = analyzers if analyzers is not None else [BanditAnalyzer()]
        # True: if any analyzer fails and nothing else was found, the result is SCAN_FAILED
        # (a PASS needs full coverage). False: a PASS may stand when an analyzer such as the
        # LLM is down, with the reduced coverage stated.
        self._strict_coverage = strict_coverage
        self._limits = limits or Limits()

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
        analyzers_failed: dict[str, str] = {}
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
                    analyzers_failed[f"{result.analyzer}@{file.path}"] = result.error or "unknown error"
            findings.extend(merge_corroborated(file_findings))

        findings.sort(key=lambda f: (f.path or "", f.line or 0, f.rule_id or ""))
        for index, finding in enumerate(findings, start=1):
            finding.id = f"f{index}"

        if prepared:
            outcome = decide(findings, sorted(analyzers_ok), analyzers_failed,
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
        findings = [Finding(**{**f.__dict__}) for f in self._findings]   # fresh copies per call
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
