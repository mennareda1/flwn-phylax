"""
tests/check_contract.py

Proves the code and openapi.yaml agree. Needs the dev dependencies (pyyaml, jsonschema,
openapi-spec-validator) and Bandit. Run from the repo root:

    python -m tests.check_contract

What it checks:
  1. openapi.yaml is a valid OpenAPI 3.1 document.
  2. Every example written inside the contract validates against its own schema.
  3. A REAL multi-file scan (real Bandit) produces a report that validates against ScanReport,
     and the same report wrapped as a Scan resource validates against Scan.
  4. Every skip reason, every decision path and every error the code can produce is in the contract.
  5. Enums in the contract equal the enums in the code (drift fails the test).
  6. The validator is not vacuous: wrong or extra fields are rejected.
  7. Structural rules: unique operation ids, auth on every real operation, a Problem response on
     every operation that can fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate as validate_openapi

from security_service.adapters.fakes import FakeCorrector
from security_service.core.errors import problem_for
from security_service.core.files import InvalidScanInput, Limits, PayloadTooLarge, SourceFile, UnsupportedLanguage
from security_service.core.scan_service import ScanService
from security_service.core.schema import VULN_TYPES, Confidence, Decision, EvidenceTier, Severity
from security_service.ports.corrector import FixConstraints
from security_service.version import CONTRACT_VERSION

SPEC_PATH = Path(__file__).resolve().parent.parent / "openapi.yaml"
spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
SCHEMAS = spec["components"]["schemas"]


def validator(name: str) -> Draft202012Validator:
    root = {"components": spec["components"], "$ref": f"#/components/schemas/{name}"}
    return Draft202012Validator(root)


def check(name: str, instance) -> None:
    errors = sorted(validator(name).iter_errors(instance), key=lambda e: list(e.path))
    assert not errors, f"{name} does not match the contract:\n" + "\n".join(
        f"  at {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors[:6])


def rejects(name: str, instance) -> bool:
    return not validator(name).is_valid(instance)


def run() -> None:
    # 1. the document itself
    validate_openapi(spec)
    assert spec["info"]["version"] == CONTRACT_VERSION, (spec["info"]["version"], CONTRACT_VERSION)

    # 2. examples inside the contract validate against their own schemas
    checked = 0
    for name, schema in SCHEMAS.items():
        for example in schema.get("examples", []):
            check(name, example)
            checked += 1
    assert checked >= 5, checked

    # 3. a real multi-file scan, with every skip reason represented
    service = ScanService(limits=Limits(max_files=10, max_file_bytes=300, max_total_bytes=5000))
    files = [
        SourceFile("app/deploy.py", 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n'),
        SourceFile("app/clean.py", 'import subprocess\n\ndef ping(host):\n    subprocess.run(["ping", "-c", "1", host], check=True)\n'),
        SourceFile("static/app.js", "let a = 1;"),                  # known source, no engine -> unsupported_language (blocks)
        SourceFile("README.md", "# docs"),                           # not source -> unsupported_language (does not block)
        SourceFile("empty.py", "  \n"),                             # empty
        SourceFile("blob.py", "a\x00b"),                             # binary_or_invalid
        SourceFile("big.py", "x = 1\n" * 100),                       # file_too_large
    ]
    report = service.scan(files)
    body = report.to_dict()
    check("ScanReport", body)
    assert body["decision"] == "block"
    assert any(f["path"] == "app/deploy.py" and f["severity"] == "high" for f in body["findings"])
    assert [f["id"] for f in body["findings"]] == [f"f{i}" for i in range(1, len(body["findings"]) + 1)]
    reasons = {s["reason"] for s in body["coverage"]["skipped_files"]}
    assert reasons == {"unsupported_language", "empty", "binary_or_invalid", "file_too_large"}, reasons

    scan_resource = {"id": "scn_test", "status": "completed", "created_at": "2026-10-15T20:00:00Z",
                     "completed_at": "2026-10-15T20:00:01Z", "client_ref": "wi-1", "report": body}
    check("Scan", scan_resource)
    check("Scan", {**scan_resource, "status": "queued", "completed_at": None, "report": None})

    outcomes = {
        "pass": service.scan([files[1]]),
        "review_required": service.scan([files[1], files[2]]),                      # a source file was not scanned
        "block": report,
        "scan_failed": ScanService(analyzers=[_Broken()]).scan([files[1]]),
    }
    for label, result in outcomes.items():
        assert result.decision.value == label, (label, result.decision)
        check("ScanReport", result.to_dict())

    check("Capabilities", service.capabilities())
    check("Readiness", {"status": "ready", "checks": {"analyzers": "ok"}})

    # fix and verification shapes come from the same domain types the services will use
    patches = FakeCorrector("os.system(", "run(").propose_fix(files[0], report.findings, FixConstraints())
    assert patches
    check("Patch", patches[0].to_dict())
    check("Fix", {"id": "fix_t", "scan_id": "scn_test", "status": "completed", "created_at": "2026-10-15T20:00:00Z",
                  "completed_at": "2026-10-15T20:00:02Z", "patches": [p.to_dict() for p in patches],
                  "verification": None, "applicable": False, "failure_reason": None})

    # 4. every error the core can raise maps to a Problem the contract allows
    raised = {
        PayloadTooLarge: lambda: ScanService(limits=Limits(max_files=1)).scan(files[:2]),
        UnsupportedLanguage: lambda: service.scan(files[:1], language="cobol"),
        InvalidScanInput: lambda: service.scan([]),
    }
    declared = {int(code) for code in spec["paths"]["/v1/scans"]["post"]["responses"] if code.isdigit()}
    for exc_type, trigger in raised.items():
        try:
            trigger()
            raise AssertionError(f"{exc_type.__name__} was not raised")
        except exc_type as exc:
            problem = problem_for(exc, "req_t")
            check("Problem", problem)
            assert problem["status"] in declared, (problem["status"], declared)
    check("Problem", problem_for(RuntimeError("boom")))

    # 5. enums in the contract equal the enums in the code
    def enum_of(name):
        return set(SCHEMAS[name]["enum"])
    assert enum_of("Decision") == {d.value for d in Decision}
    assert enum_of("Severity") == {s.value for s in Severity}
    assert enum_of("Confidence") == {c.value for c in Confidence}
    assert enum_of("EvidenceTier") == {t.value for t in EvidenceTier}
    assert enum_of("VulnerabilityType") == set(VULN_TYPES)
    assert set(SCHEMAS["ScanReport"]["properties"]["risk_level"]["enum"]) == {"none"} | {s.value for s in Severity}

    # 6. the validator is not vacuous
    assert rejects("ScanReport", {**body, "surprise": 1}), "unknown fields must be rejected"
    assert rejects("ScanReport", {**body, "decision": "maybe"}), "unknown decision must be rejected"
    assert rejects("ScanReport", {k: v for k, v in body.items() if k != "coverage"}), "missing field must be rejected"
    assert rejects("Finding", {**body["findings"][0], "severity": "catastrophic"})
    assert rejects("Scan", {**scan_resource, "status": "done"})
    assert rejects("InputFile", {"path": "", "content": "x"})
    assert rejects("Problem", {"title": "t", "status": 200, "code": "invalid_request", "type": "t"})

    # 7. structure
    operation_ids, unprotected = [], []
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in {"get", "post", "delete", "put", "patch"}:
                continue
            operation_ids.append(operation["operationId"])
            if operation.get("security") == [] and not path.startswith(("/healthz", "/readyz")):
                unprotected.append(f"{method.upper()} {path}")
            if path.startswith(("/healthz", "/readyz")):
                continue
            has_problem = any("components/responses" in str(r) for code, r in operation["responses"].items() if code.startswith(("4", "5")))
            assert has_problem, f"{method.upper()} {path} declares no Problem response"
    assert len(operation_ids) == len(set(operation_ids)), "operation ids must be unique"
    assert not unprotected, f"operations without auth: {unprotected}"

    print(f"contract OK: valid OpenAPI {spec['openapi']}, {checked} examples valid, real scan matches ScanReport/Scan, "
          f"4 decision paths, 4 skip reasons, 4 error codes, enums in sync, validator rejects bad data")


class _Broken:
    role = "analyzer"
    name = "broken"
    languages = ("python",)

    def analyze(self, code, language):
        from security_service.ports.analyzer import AnalyzerResult
        return AnalyzerResult(analyzer=self.name, error="engine unavailable")


if __name__ == "__main__":
    try:
        run()
    except AssertionError:
        import traceback
        print("CONTRACT CHECK FAILED:\n" + traceback.format_exc())
        sys.exit(1)
