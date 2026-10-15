"""
security_service/adapters/bandit.py

Python lane, static rules: runs Bandit on the submitted code and converts its
JSON output into our normalized Finding objects.

Safety notes:
  - The code is only parsed, never executed.
  - Runs as a subprocess with a timeout, in a throwaway temp directory.
  - Uses --ignore-nosec: code under review (especially AI-written code) must
    not be able to silence the scanner with a "# nosec" comment. Verified:
    by default a single "# nosec" hides a HIGH-severity shell=True finding.
  - Day 3 hardening still to do: memory limits, a minimal environment for
    the subprocess, and no network.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from security_service.ports.analyzer import AnalyzerResult
from security_service.core.redaction import mask_for_report
from security_service.core.schema import (
    RECOMMENDATIONS,
    Confidence,
    EvidenceTier,
    Finding,
    Severity,
)

BANDIT_TIMEOUT_SECONDS = 30

# Rule-specific mapping wins over CWE mapping, because Bandit's CWE tags are
# coarse (e.g. it tags eval() with CWE-78, the OS-command-injection id).
RULE_TO_TYPE = {
    "B102": "code_injection",              # exec
    "B307": "code_injection",              # eval
    "B201": "debug_enabled",               # flask debug=True
    "B608": "sql_injection",               # string-built SQL
    "B501": "tls_verification_disabled",   # requests verify=False
    "B323": "tls_verification_disabled",   # unverified ssl context
    "B306": "insecure_temp_file",          # tempfile.mktemp
    "B108": "insecure_temp_file",          # hardcoded /tmp path
    "B311": "insecure_random",             # random module
    "B701": "xss_or_template_injection",   # jinja2 autoescape=False
    "B506": "insecure_deserialization",    # yaml.load (Bandit tags it CWE-20)
}

CWE_TO_TYPE = {
    77: "command_injection", 78: "command_injection",
    89: "sql_injection",
    94: "code_injection", 95: "code_injection",
    259: "hardcoded_credentials", 321: "hardcoded_credentials", 798: "hardcoded_credentials",
    502: "insecure_deserialization",
    326: "weak_crypto", 327: "weak_crypto", 328: "weak_crypto",
    330: "insecure_random", 338: "insecure_random",
    22: "path_traversal",
    918: "ssrf",
    79: "xss_or_template_injection", 80: "xss_or_template_injection",
    295: "tls_verification_disabled",
    377: "insecure_temp_file", 379: "insecure_temp_file",
}

_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
_CONFIDENCE = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


def _classify(test_id: str, cwe_id: int | None) -> str:
    if test_id in RULE_TO_TYPE:
        return RULE_TO_TYPE[test_id]
    if cwe_id in CWE_TO_TYPE:
        return CWE_TO_TYPE[cwe_id]
    return "other"


def _evidence_line(code_lines: list[str], line_number: int | None, vuln_type: str) -> str:
    """The offending line from the ORIGINAL code, with secret values masked."""
    if not line_number or line_number > len(code_lines):
        return ""
    return mask_for_report(code_lines[line_number - 1].strip(), vuln_type)[:200]


class BanditAnalyzer:
    role = "analyzer"
    name = "bandit"
    languages = ("python",)

    def analyze(self, code: str, language: str) -> AnalyzerResult:
        start = time.monotonic()

        def done(**kw) -> AnalyzerResult:
            return AnalyzerResult(analyzer=self.name, duration_ms=int((time.monotonic() - start) * 1000), **kw)

        if language not in self.languages:
            return done(error=f"bandit does not support language {language!r}")

        env = dict(os.environ, PYTHONUTF8="1")
        with tempfile.TemporaryDirectory(prefix="flwn_scan_") as tmp:
            path = Path(tmp) / "snippet.py"
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(code)
            cmd = [sys.executable, "-m", "bandit", "-f", "json", "--exit-zero", "-q",
                   "--ignore-nosec", str(path)]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, encoding="utf-8",
                    timeout=BANDIT_TIMEOUT_SECONDS, env=env, cwd=tmp,
                )
            except subprocess.TimeoutExpired:
                return done(error=f"bandit timed out after {BANDIT_TIMEOUT_SECONDS}s")
            except OSError as exc:
                return done(error=f"could not start bandit: {exc}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = (proc.stderr or proc.stdout or "no output").strip()[:200]
            return done(error=f"bandit produced unreadable output (exit {proc.returncode}): {detail}")

        if data.get("errors"):
            reason = data["errors"][0].get("reason", "unknown error")
            return done(error=f"bandit could not analyze the code: {reason}")

        code_lines = code.splitlines()
        findings: list[Finding] = []
        for item in data.get("results", []):
            cwe_id = (item.get("issue_cwe") or {}).get("id")
            test_id = item.get("test_id", "")
            vuln_type = _classify(test_id, cwe_id)
            line = item.get("line_number")
            findings.append(Finding(
                vulnerability_type=vuln_type,
                severity=_SEVERITY.get(item.get("issue_severity", ""), Severity.LOW),
                confidence=_CONFIDENCE.get(item.get("issue_confidence", ""), Confidence.LOW),
                evidence_tier=EvidenceTier.STATIC_RULE,
                sources=[self.name],
                rule_id=test_id or None,
                cwe=f"CWE-{cwe_id}" if cwe_id else None,
                line=line,
                evidence=_evidence_line(code_lines, line, vuln_type),
                description=item.get("issue_text", ""),
                recommendation=RECOMMENDATIONS.get(vuln_type, RECOMMENDATIONS["other"]),
                reference=item.get("more_info"),
            ))
        findings.sort(key=lambda f: (f.line or 0, f.rule_id or ""))
        return done(findings=findings)
