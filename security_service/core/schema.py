"""
security_service/core/schema.py

Data shapes shared by every part of the service. They mirror the response schemas in
openapi.yaml; tests/check_contract.py proves the two stay in agreement.

Design rules baked in:
  - severity (how bad if real) and confidence (how sure the evidence is) are separate, and
    confidence is a coarse level, never a fake-precise probability.
  - every finding records where its evidence came from (evidence_tier), because the decision
    policy treats rule-backed and model-only findings differently.
  - every report carries a coverage statement, so a PASS is never read as "this code is safe",
    only "nothing was found by the checks that ran, on the files that were scanned".
  - provenance records which engines and policy produced a result, for audit only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


class EvidenceTier(str, Enum):
    STATIC_RULE = "static_rule"          # a deterministic analyzer rule matched
    MODEL_SUSPICION = "model_suspicion"  # only a model flagged it
    CORROBORATED = "corroborated"        # both kinds of source agree


class Decision(str, Enum):
    PASS = "pass"
    REVIEW_REQUIRED = "review_required"
    BLOCK = "block"
    SCAN_FAILED = "scan_failed"


# Canonical vulnerability categories. Adapters map their own rule ids / CWEs onto these so
# findings from different engines are comparable.
VULN_TYPES = (
    "command_injection",
    "sql_injection",
    "code_injection",
    "hardcoded_credentials",
    "insecure_deserialization",
    "weak_crypto",
    "insecure_random",
    "path_traversal",
    "ssrf",
    "xss_or_template_injection",
    "tls_verification_disabled",
    "debug_enabled",
    "insecure_temp_file",
    "other",
)

RECOMMENDATIONS = {
    "command_injection": "Avoid shell execution. Pass arguments as a list (no shell=True) and validate or allow-list any user-controlled values.",
    "sql_injection": "Use parameterized queries; never build SQL with string formatting or concatenation.",
    "code_injection": "Do not evaluate user-controlled text as code. Use ast.literal_eval or a purpose-built parser.",
    "hardcoded_credentials": "Move secrets out of source code into environment variables or a secrets manager, and rotate any exposed value.",
    "insecure_deserialization": "Do not deserialize untrusted data with pickle or unsafe YAML loaders. Use JSON or yaml.safe_load.",
    "weak_crypto": "Use modern algorithms (SHA-256 or better; a dedicated password hash such as argon2, bcrypt or PBKDF2 for passwords).",
    "insecure_random": "Use the secrets module for tokens, passwords and anything security-sensitive.",
    "path_traversal": "Resolve the final path and verify it stays inside the intended base directory before opening it.",
    "ssrf": "Validate user-supplied URLs against an allow-list of hosts and block internal address ranges.",
    "xss_or_template_injection": "Never build templates from user input; pass values as template variables and keep auto-escaping enabled.",
    "tls_verification_disabled": "Keep certificate verification enabled; fix the certificate chain instead of disabling checks.",
    "debug_enabled": "Disable debug mode outside local development.",
    "insecure_temp_file": "Use tempfile.mkstemp or NamedTemporaryFile instead of predictable temp file names.",
    "other": "Review this finding manually.",
}

# What a scan of submitted files cannot see. Included in every report so a PASS is never
# mistaken for a safety guarantee.
NOT_ASSESSABLE_FROM_SUBMITTED_FILES = (
    "authentication and authorization logic (needs the surrounding application)",
    "data flow across services and files that were not submitted",
    "vulnerabilities in third-party dependencies",
    "deployment, configuration and runtime behavior",
)


@dataclass
class Finding:
    vulnerability_type: str
    severity: Severity
    confidence: Confidence
    evidence_tier: EvidenceTier
    sources: list[str]
    rule_id: str | None
    cwe: str | None
    line: int | None
    evidence: str
    description: str
    recommendation: str
    reference: str | None = None
    path: str | None = None     # which submitted file; set by the scan service
    id: str = ""                # "f1", "f2", ...; stable within one report; set by the scan service

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence_tier": self.evidence_tier.value,
            "sources": list(self.sources),
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "line": self.line,
            "evidence": self.evidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "reference": self.reference,
        }


@dataclass
class SkippedFile:
    path: str
    reason: str          # unsupported_language | file_too_large | binary_or_invalid | empty
    blocks_pass: bool    # True for source files: a report with such a file can never be a pass

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": self.reason, "blocks_pass": self.blocks_pass}


@dataclass
class Coverage:
    languages: list[str] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    skipped_files: list[SkippedFile] = field(default_factory=list)
    analyzers_run: list[str] = field(default_factory=list)
    analyzers_failed: dict[str, str] = field(default_factory=dict)
    not_assessable: list[str] = field(default_factory=lambda: list(NOT_ASSESSABLE_FROM_SUBMITTED_FILES))

    def to_dict(self) -> dict[str, Any]:
        return {
            "languages": list(self.languages),
            "files_scanned": list(self.files_scanned),
            "skipped_files": [s.to_dict() for s in self.skipped_files],
            "analyzers_run": list(self.analyzers_run),
            "analyzers_failed": dict(self.analyzers_failed),
            "not_assessable": list(self.not_assessable),
        }


@dataclass
class Engine:
    role: str    # analyzer | detector | classifier | corrector
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "name": self.name}


@dataclass
class Provenance:
    """Which versions and engines produced a result. Audit only: clients must not branch on it."""

    contract_version: str
    service_version: str
    policy_version: str
    engines: list[Engine] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "service_version": self.service_version,
            "policy_version": self.policy_version,
            "engines": [e.to_dict() for e in self.engines],
        }


def highest_severity(findings: list[Finding]) -> str:
    """Worst severity among findings, or 'none'. Describes the findings, not the code's safety."""
    if not findings:
        return "none"
    return max((f.severity for f in findings), key=lambda s: s.rank).value


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in reversed(list(Severity))}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total_findings": len(findings), **counts}


@dataclass
class ScanReport:
    status: str                       # "completed" | "failed"
    decision: Decision
    risk_level: str
    findings: list[Finding]
    summary: dict[str, int]
    decision_reasons: list[str]
    coverage: Coverage
    provenance: Provenance
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "decision": self.decision.value,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
            "summary": dict(self.summary),
            "decision_reasons": list(self.decision_reasons),
            "coverage": self.coverage.to_dict(),
            "provenance": self.provenance.to_dict(),
            "duration_ms": self.duration_ms,
        }
