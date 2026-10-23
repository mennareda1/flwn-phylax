"""
tests/run_all.py

Runs every self-check in the repo, one process each, and prints a one-line result per check.
Run from the repo root:

    python -m tests.run_all

Needs: bandit (the real rules engine) and, for the contract check, pyyaml, jsonschema and
openapi-spec-validator. Exit code is non-zero if anything fails.
"""

from __future__ import annotations

import subprocess
import sys

CHECKS = [
    "security_service.ports.llm",
    "security_service.ports.classifier",
    "security_service.ports.corrector",
    "security_service.adapters.llm_clients",
    "security_service.adapters.foundry_llm",
    "security_service.adapters.fakes",
    "security_service.adapters.secrets_check",
    "security_service.adapters.decision1",
    "security_service.adapters.llm_detector",
    "security_service.core.redaction",
    "security_service.core.files",
    "security_service.core.patching",
    "security_service.core.decision",
    "security_service.core.errors",
    "security_service.core.scan_service",
    "benchmark.cases_python",
    "benchmark.bakeoff",
    "tests.check_contract",
]


def main() -> int:
    failures = []
    for module in CHECKS:
        done = subprocess.run([sys.executable, "-m", module], capture_output=True, text=True, encoding="utf-8")
        lines = (done.stdout or "").strip().splitlines()
        summary = next((line for line in reversed(lines) if "OK" in line), lines[-1] if lines else "")
        if done.returncode == 0:
            print(f"ok     {module:<42} {summary[:90]}")
        else:
            failures.append(module)
            print(f"FAILED {module}\n{(done.stdout + done.stderr).strip()[-1500:]}")
    print(f"\n{len(CHECKS) - len(failures)}/{len(CHECKS)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
