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
# Developer settings that change how a Python program starts (extra import folders, a start-up script, an interactive prompt afterwards). The service may be run with
# them while it is being developed; the engine it launches must not inherit them.
_NOT_FOR_THE_CHILD = ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT")


def child_environment() -> dict[str, str]:
    """The environment Bandit is started with: the service's own, minus the developer settings above, with UTF-8 forced."""
    env = {name: value for name, value in os.environ.items() if name.upper() not in _NOT_FOR_THE_CHILD}
    env["PYTHONUTF8"] = "1"
    return env


def _said_before_stalling(exc: "subprocess.TimeoutExpired") -> str:
    """Whatever Bandit printed before it was stopped, in a few safe words, so that a stall explains itself instead of just saying 'timed out'."""
    parts = []
    for stream in (exc.stderr, exc.stdout):
        text = stream.decode("utf-8", "replace") if isinstance(stream, bytes) else (stream or "")
        text = " ".join(text.split())
        if text:
            parts.append(text[:200])
    return f" (it printed: {' | '.join(parts)})" if parts else " (it printed nothing before it was stopped)"

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

        env = child_environment()
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
                    stdin=subprocess.DEVNULL,                # the service's own input is never handed to a child: a child that waits on it would wait forever
                )
            except subprocess.TimeoutExpired as exc:
                return done(error=f"bandit timed out after {BANDIT_TIMEOUT_SECONDS}s" + _said_before_stalling(exc))
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


def demo() -> None:
    """The launch is hardened, a stall explains itself, and the real Bandit still works with the developer settings present."""
    import tempfile

    analyzer = BanditAnalyzer()
    real_run, seen = subprocess.run, {}

    class Done:
        returncode, stderr, stdout = 0, "", '{"results": [], "errors": []}'

    def spy(cmd, **kwargs):
        seen.update(kwargs, cmd=cmd)
        return Done()

    saved = {name: os.environ.get(name) for name in ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "PHYLAX_DEMO_SETTING")}
    os.environ.update({"PYTHONPATH": "/some/dev/folder", "PYTHONSTARTUP": "/some/startup.py", "PYTHONINSPECT": "1", "PHYLAX_DEMO_SETTING": "kept"})
    try:
        subprocess.run = spy
        assert analyzer.analyze("x = 1\n", "python").ok
        assert seen["stdin"] is subprocess.DEVNULL, "the child never inherits the service's input"
        for name in ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"):
            assert name not in seen["env"], f"{name} must not reach the child"
        assert seen["env"]["PYTHONUTF8"] == "1" and seen["env"]["PHYLAX_DEMO_SETTING"] == "kept", "everything else is kept"
        assert seen["timeout"] == BANDIT_TIMEOUT_SECONDS and Path(seen["cwd"]).name.startswith("flwn_scan_") and seen["cmd"][1:3] == ["-m", "bandit"]
        assert child_environment().get("PATH") == os.environ.get("PATH"), "PATH and the rest of the system's settings are untouched"

        def stalled(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 30, output=b"partial\nout", stderr=b"Traceback: it\nwas waiting " + b"x" * 400)

        subprocess.run = stalled
        result = analyzer.analyze("x = 1\n", "python")
        assert not result.ok and "bandit timed out after 30s (it printed: Traceback: it was waiting xxxx" in result.error and "partial out" in result.error
        assert "\n" not in result.error and len(result.error) < 450, "the explanation is one short line"

        def silent(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 30)

        subprocess.run = silent
        assert analyzer.analyze("x = 1\n", "python").error.endswith("(it printed nothing before it was stopped)")
    finally:
        subprocess.run = real_run
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    # the REAL Bandit, with the developer settings present in the environment, still runs and still finds the problem
    os.environ.update({"PYTHONPATH": tempfile.gettempdir(), "PYTHONINSPECT": "1"})
    try:
        real = analyzer.analyze("import os\n\ndef ping(host):\n    os.system('ping ' + host)\n", "python")
        assert real.ok and [f.vulnerability_type for f in real.findings] == ["command_injection"], real.error
        assert analyzer.analyze("x = 1\n", "javascript").ok is False
    finally:
        for name in ("PYTHONPATH", "PYTHONINSPECT"):
            if saved[name] is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = saved[name]
    print("adapters.bandit OK: the child never inherits the service's input or its developer settings, a stall says what Bandit printed, the real Bandit still finds the problem")


if __name__ == "__main__":
    demo()
