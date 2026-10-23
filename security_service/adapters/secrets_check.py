"""
security_service/adapters/secrets_check.py

Deterministic secrets check: finds credentials written into source code. No model, no network, no
license question; it is our own code, built on the same patterns that mask secrets before a model
sees the code (core/redaction.py).

Policy, recorded here and in the README:
  - Reports only STRICT matches (values that could plausibly be a real secret). Names, header names,
    environment-variable names, paths, URLs, dates and versions are never reported.
  - Severity: a value in a known secret format (cloud key, access token, JWT, bearer token, private
    key) is HIGH; a probable secret assigned to a credential-named variable is MEDIUM.
  - Confidence is always MEDIUM: a pattern cannot tell a live key from the documented example key.
    The decision policy blocks only on HIGH confidence, so a secret found by pattern asks for human
    review but never blocks on its own.
  - One finding per line. The evidence line has every secret value masked.

Python only for now. A file in another language must not count as "scanned" because this check
alone ran on it: a pass would then rest on secrets coverage and nothing else. Widen the language
list together with each language's rules engine.
"""

from __future__ import annotations

import time

from security_service.core.redaction import SecretHit, mask_for_report, scan_secrets
from security_service.core.schema import (
    RECOMMENDATIONS,
    Confidence,
    EvidenceTier,
    Finding,
    Severity,
)
from security_service.ports.analyzer import AnalyzerResult

_KNOWN_KINDS = {"known_token", "bearer_token", "private_key"}

_DESCRIPTIONS = {
    "private_key": ("SECRET-KEY-BLOCK", "A private key is embedded in the source."),
    "known_token": ("SECRET-TOKEN", "A value in the format of a live access key or token is written into the source."),
    "bearer_token": ("SECRET-TOKEN", "A value in the format of a live access key or token is written into the source."),
    "credential_assignment": ("SECRET-ASSIGN", "A value that looks like a real secret is assigned to a credential-named variable."),
}


def _strongest_kind(hits: list[SecretHit]) -> str:
    for kind in ("private_key", "known_token", "bearer_token"):
        if any(h.kind == kind for h in hits):
            return kind
    return "credential_assignment"


class SecretsAnalyzer:
    role = "analyzer"
    name = "secrets"
    languages = ("python",)

    def analyze(self, code: str, language: str) -> AnalyzerResult:
        started = time.monotonic()
        if language not in self.languages:
            return AnalyzerResult(analyzer=self.name, error=f"secrets check does not support language {language!r}")

        lines = code.split("\n")
        strict_hits: dict[int, list[SecretHit]] = {}
        for number, hit in scan_secrets(code):
            if hit.strict:
                strict_hits.setdefault(number, []).append(hit)

        findings: list[Finding] = []
        for number, hits in sorted(strict_hits.items()):
            kind = _strongest_kind(hits)
            rule_id, description = _DESCRIPTIONS[kind]
            findings.append(Finding(
                vulnerability_type="hardcoded_credentials",
                severity=Severity.HIGH if kind in _KNOWN_KINDS else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence_tier=EvidenceTier.STATIC_RULE,
                sources=[self.name],
                rule_id=rule_id,
                cwe="CWE-798",
                line=number,
                evidence=mask_for_report(lines[number - 1].strip(), "hardcoded_credentials")[:200],
                description=description,
                recommendation=RECOMMENDATIONS["hardcoded_credentials"],
            ))
        return AnalyzerResult(analyzer=self.name, findings=findings, duration_ms=int((time.monotonic() - started) * 1000))


def demo() -> None:
    analyzer = SecretsAnalyzer()
    secret_values = ["SuperSecret123!", "sk-live-EXAMPLE0000000000000000", "hunter22", "AKIAIOSFODNN7EXAMPLE",
                     "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"]
    code = (
        'DB_PASSWORD = "SuperSecret123!"\n'                                              # 1  MEDIUM
        'API_KEY = "sk-live-EXAMPLE0000000000000000"\n'                                  # 2  HIGH (known format + credential name)
        'cfg = {"password": "hunter22"}\n'                                               # 3  MEDIUM
        'aws = "AKIAIOSFODNN7EXAMPLE"\n'                                                 # 4  HIGH (known format, no credential name)
        'GITHUB_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"\n'                    # 5  HIGH
        'KEY = """-----BEGIN RSA PRIVATE KEY-----\n'                                      # 6  HIGH (private key, reported once)
        'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n'             # 7  (body: not reported separately)
        '-----END RSA PRIVATE KEY-----"""\n'                                             # 8
        'API_KEY_HEADER = "X-Api-Key"\n'                                                 # 9  not a secret
        'PASSWORD_ENV_VAR = "DB_PASSWORD"\n'
        'SECRET_PATH = "prod/db/credentials"\n'
        'API_KEY_VERSION = "2024-01-01"\n'
        'TOKEN_URL = "https://auth.example.com/oauth/token"\n'
        'password = os.environ["DB_PASSWORD"]\n'
        'x = 1\n'
    )
    result = analyzer.analyze(code, "python")
    assert result.ok
    got = [(f.line, f.severity.value, f.rule_id) for f in result.findings]
    assert got == [(1, "medium", "SECRET-ASSIGN"), (2, "high", "SECRET-TOKEN"), (3, "medium", "SECRET-ASSIGN"),
                   (4, "high", "SECRET-TOKEN"), (5, "high", "SECRET-TOKEN"), (6, "high", "SECRET-KEY-BLOCK")], got

    for finding in result.findings:
        assert finding.vulnerability_type == "hardcoded_credentials" and finding.cwe == "CWE-798"
        assert finding.confidence == Confidence.MEDIUM          # a pattern can never reach the confidence that blocks
        assert finding.evidence_tier == EvidenceTier.STATIC_RULE and finding.sources == ["secrets"]
        rendered = str(finding.to_dict())
        for value in secret_values:
            assert value not in rendered, f"secret leaked into a finding: {value}"
    assert result.findings[0].evidence == 'DB_PASSWORD = "***"'

    assert analyzer.analyze("x = 1\n", "python").findings == []
    assert not analyzer.analyze("let a = 1", "javascript").ok
    print("adapters.secrets OK: six real secrets reported, six lookalikes not, no secret value in any finding, never high confidence")


if __name__ == "__main__":
    demo()
