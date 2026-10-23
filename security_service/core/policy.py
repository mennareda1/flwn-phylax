"""
security_service/core/policy.py

The decision policy: turns findings and coverage into PASS / REVIEW_REQUIRED / BLOCK /
SCAN_FAILED. Pure Python, no tools, no model calls, on purpose. The policy must be
explainable and testable, so no model is ever asked "is this safe?".

Rules (thresholds below are the knobs; bump POLICY_VERSION in version.py when they change):
  - BLOCK only on a rule-backed finding that is high severity AND high confidence.
    A model-only finding can never block.
  - REVIEW_REQUIRED for any other rule-backed finding at medium severity or above, or a
    model-only finding at medium or above.
  - PASS when nothing reaches the review threshold, which means "nothing found by the checks
    that ran on the files that were scanned", never "safe".
  - A SOURCE file that was not scanned (unsupported language, too large, corrupt) makes a
    would-be PASS into REVIEW_REQUIRED. The scan did run, but a human must know it was partial.
  - SCAN_FAILED when no analyzer completed on files that were attempted, or when an analyzer
    failed and the rest found nothing (a PASS needs full coverage).
  - Nothing to scan (no source files at all) is a PASS that says so explicitly; source files that
    could not be scanned are REVIEW_REQUIRED.
Flwn treats review_required and scan_failed alike: never a pass, human review required.
"""

from __future__ import annotations

from dataclasses import dataclass

from security_service.core.schema import (
    Confidence,
    Decision,
    EvidenceTier,
    Finding,
    Severity,
)

BLOCK_MIN_SEVERITY = Severity.HIGH
BLOCK_MIN_CONFIDENCE = Confidence.HIGH
REVIEW_MIN_SEVERITY = Severity.MEDIUM

TOOL_BACKED = (EvidenceTier.STATIC_RULE, EvidenceTier.CORROBORATED)


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reasons: tuple[str, ...]


def _types(findings: list[Finding]) -> str:
    return ", ".join(sorted({f.vulnerability_type for f in findings}))


def decide(
    findings: list[Finding],
    analyzers_ok: list[str],
    analyzers_failed: dict[str, str],
    strict_coverage: bool = True,
    skipped_blocking: int = 0,
    notes: tuple[str, ...] = (),
) -> DecisionResult:
    if not analyzers_ok:
        reasons = ["No analyzer completed successfully."]
        reasons += [f"{name}: {error}" for name, error in analyzers_failed.items()]
        return DecisionResult(Decision.SCAN_FAILED, tuple(reasons) + notes)

    tool = [f for f in findings if f.evidence_tier in TOOL_BACKED]
    model = [f for f in findings if f.evidence_tier == EvidenceTier.MODEL_SUSPICION]

    blockers = [
        f for f in tool
        if f.severity.rank >= BLOCK_MIN_SEVERITY.rank
        and f.confidence.rank >= BLOCK_MIN_CONFIDENCE.rank
    ]
    tool_review = [f for f in tool if f.severity.rank >= REVIEW_MIN_SEVERITY.rank]
    model_review = [f for f in model if f.severity.rank >= REVIEW_MIN_SEVERITY.rank]

    if blockers:
        decision = Decision.BLOCK
        reasons = [
            f"{len(blockers)} high-severity, high-confidence finding(s) backed by "
            f"static analysis ({_types(blockers)})."
        ]
    elif tool_review:
        decision = Decision.REVIEW_REQUIRED
        reasons = [
            f"{len(tool_review)} static-analysis finding(s) at medium severity or "
            f"above need a human look ({_types(tool_review)})."
        ]
    elif model_review:
        decision = Decision.REVIEW_REQUIRED
        reasons = [
            f"{len(model_review)} finding(s) rest on model suspicion alone "
            f"({_types(model_review)}); a model alone never blocks."
        ]
    else:
        decision = Decision.PASS
        reasons = [
            "Nothing reached the review threshold within the checks that ran. "
            "This is not a guarantee the code is secure."
        ]

    if skipped_blocking:
        message = f"{skipped_blocking} source file(s) were not scanned, so coverage is incomplete."
        if decision == Decision.PASS:
            decision = Decision.REVIEW_REQUIRED
            reasons = [message + " A pass needs every source file scanned."]
        else:
            reasons.append(message)

    if analyzers_failed:
        failed = "; ".join(f"{name}: {error}" for name, error in analyzers_failed.items())
        if decision == Decision.PASS and strict_coverage:
            return DecisionResult(
                Decision.SCAN_FAILED,
                (f"Some analyzers failed ({failed}), so a PASS cannot be issued.",) + notes,
            )
        reasons.append(f"Coverage is reduced because some analyzers failed ({failed}).")

    return DecisionResult(decision, tuple(reasons) + notes)


def decide_nothing_scanned(skipped_blocking: int, notes: tuple[str, ...] = ()) -> DecisionResult:
    """No file was analyzed at all (every file was skipped). Not the same as a failed scan."""
    if skipped_blocking:
        return DecisionResult(
            Decision.REVIEW_REQUIRED,
            (f"{skipped_blocking} source file(s) could not be scanned; nothing was checked.",) + notes,
        )
    return DecisionResult(
        Decision.PASS,
        ("No source files to scan, so nothing was checked. This is not a guarantee about the change.",) + notes,
    )


def _finding(severity, confidence, tier=EvidenceTier.STATIC_RULE, vtype="command_injection") -> Finding:
    return Finding(
        vulnerability_type=vtype, severity=severity, confidence=confidence,
        evidence_tier=tier, sources=["demo"], rule_id="X1", cwe=None, line=1,
        evidence="x", description="d", recommendation="r",
    )


def demo() -> None:
    """Assert-based self-check, same convention as the other services (no pytest)."""
    H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
    hc, mc = Confidence.HIGH, Confidence.MEDIUM
    ok, failed = ["a"], {}

    assert decide([], ok, failed).decision == Decision.PASS

    # BLOCK needs rule-backed + high severity + high confidence
    assert decide([_finding(H, hc)], ok, failed).decision == Decision.BLOCK
    assert decide([_finding(Severity.CRITICAL, hc, EvidenceTier.CORROBORATED)], ok, failed).decision == Decision.BLOCK
    assert decide([_finding(H, mc)], ok, failed).decision == Decision.REVIEW_REQUIRED
    assert decide([_finding(M, hc)], ok, failed).decision == Decision.REVIEW_REQUIRED

    # a model alone can never block, however severe it claims to be
    model_high = _finding(Severity.CRITICAL, hc, EvidenceTier.MODEL_SUSPICION)
    assert decide([model_high], ok, failed).decision == Decision.REVIEW_REQUIRED
    assert decide([_finding(M, hc, EvidenceTier.MODEL_SUSPICION)], ok, failed).decision == Decision.REVIEW_REQUIRED

    # low severity alone does not trigger review
    assert decide([_finding(L, hc)], ok, failed).decision == Decision.PASS

    # nothing ran -> SCAN_FAILED, never PASS
    assert decide([], [], {"a": "boom"}).decision == Decision.SCAN_FAILED

    # partial failure: PASS is downgraded; a real finding keeps its decision
    assert decide([], ["a"], {"b": "timeout"}).decision == Decision.SCAN_FAILED
    partial = decide([_finding(H, hc)], ["a"], {"b": "timeout"})
    assert partial.decision == Decision.BLOCK and any("reduced" in r for r in partial.reasons)

    # relaxed coverage lets a PASS stand when an analyzer is down, with the gap stated
    relaxed = decide([], ["a"], {"b": "timeout"}, strict_coverage=False)
    assert relaxed.decision == Decision.PASS and any("reduced" in r for r in relaxed.reasons)
    assert decide([], [], {"a": "x"}, strict_coverage=False).decision == Decision.SCAN_FAILED

    # skipped SOURCE files: a would-be PASS becomes REVIEW_REQUIRED; real findings keep their decision
    skipped = decide([], ok, failed, skipped_blocking=2)
    assert skipped.decision == Decision.REVIEW_REQUIRED and "2 source file(s)" in skipped.reasons[0]
    kept = decide([_finding(H, hc)], ok, failed, skipped_blocking=1)
    assert kept.decision == Decision.BLOCK and any("not scanned" in r for r in kept.reasons)

    # notes are appended to every outcome
    assert decide([], ok, failed, notes=("n1",)).reasons[-1] == "n1"
    assert decide([], [], {"a": "x"}, notes=("n2",)).reasons[-1] == "n2"

    # nothing scanned at all: no source files -> explicit PASS; unscannable source files -> REVIEW_REQUIRED
    assert decide_nothing_scanned(0).decision == Decision.PASS
    assert "nothing was checked" in decide_nothing_scanned(0).reasons[0]
    assert decide_nothing_scanned(3).decision == Decision.REVIEW_REQUIRED

    print("core.policy OK: block/review/pass thresholds, model-only never blocks, failures and skipped source files never PASS")


if __name__ == "__main__":
    demo()
