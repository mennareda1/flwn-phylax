"""
tests/run_all.py

Runs every self-check in the repo, one process each, and prints a one-line result per check.
Run from the repo root:

    python -m tests.run_all

Needs: bandit (the real rules engine) and, for the contract check, pyyaml, jsonschema and
openapi-spec-validator. Exit code is non-zero if anything fails.
"""

from __future__ import annotations

import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

CHECKS = [
    "tests.run_all --selftest",
    "security_service.ports.llm",
    "security_service.ports.classifier",
    "security_service.ports.corrector",
    "security_service.adapters.llm_clients",
    "security_service.adapters.foundry_llm",
    "security_service.adapters.fakes",
    "security_service.adapters.secrets_check",
    "security_service.adapters.decision1",
    "security_service.adapters.classifier_detector",
    "security_service.adapters.bandit",
    "security_service.adapters.js_rules",
    "security_service.adapters.foundry_chat",
    "security_service.adapters.foundry_corrector",
    "security_service.adapters.llm_detector",
    "security_service.core.redaction",
    "security_service.core.files",
    "security_service.core.patching",
    "security_service.core.policy",
    "security_service.core.errors",
    "security_service.core.questions",
    "security_service.core.scan_service",
    "security_service.core.verification",
    "security_service.core.fix_service",
    "security_service.fix --selftest",
    "security_service.paths",
    "security_service.paths",
    "security_service.scan --selftest",
    "security_service.api.auth",
    "security_service.api.ratelimit",
    "security_service.api.jobs",
    "security_service.api.gateway",
    "security_service.api --selftest",
    "security_service.config --selftest",
    "benchmark.cases_python",
    "benchmark.cases_heldout",
    "benchmark.cases_javascript",
    "benchmark.cases_heldout_js",
    "benchmark.bakeoff",
    "benchmark.classifier_eval --selftest",
    "tests.check_layout",
    "tests.check_contract",
    "tests.check_interop",
    "tests.check_ts_client",
    "tests.check_deploy",
    "tests.live_decision1 --selftest",
    "tests.check_transport",
    "tests.check_api",
    "tests.check_service",
]


def missing_packages(requirements: str, installed=None) -> list[str]:
    """The packages in requirements.txt that are needed to run the checks but are not installed. A block that starts with a "# Optional" comment is
    skipped, and so is anything commented out. `installed(name)` is injectable for testing."""
    def is_installed(name: str) -> bool:
        try:
            metadata.version(name)
            return True
        except metadata.PackageNotFoundError:
            return False

    installed = installed or is_installed
    missing, optional = [], False
    for line in requirements.splitlines():
        stripped = line.strip()
        if not stripped:
            optional = False
        elif stripped.startswith("#"):
            optional = optional or stripped.lower().startswith("# optional")
        elif not optional:
            name = re.split(r"[<>=!~\[;\s]", stripped, maxsplit=1)[0]
            if name and not installed(name):
                missing.append(name)
    return missing


def selftest() -> None:
    text = "# Runtime: rules\nbandit\n\n# Runtime: parsers\ntree-sitter\ntree-sitter-javascript>=0.23\n\n# Optional: Azure\nazure-ai-inference\n\n# Optional: sign-in\n# azure-identity\n\nhttpx[http2]; python_version >= '3.9'\n"
    assert missing_packages(text, installed=lambda name: True) == []
    assert missing_packages(text, installed=lambda name: False) == ["bandit", "tree-sitter", "tree-sitter-javascript", "httpx"]       # optional and commented-out ones are never required
    assert missing_packages(text, installed=lambda name: name not in ("tree-sitter-javascript", "bandit")) == ["bandit", "tree-sitter-javascript"]
    assert missing_packages("", installed=lambda name: False) == [] and missing_packages("# only a comment\n", installed=lambda name: False) == []
    real = missing_packages((Path(__file__).resolve().parent.parent / "requirements.txt").read_text(encoding="utf-8"), installed=lambda name: True)
    assert real == []
    names = missing_packages((Path(__file__).resolve().parent.parent / "requirements.txt").read_text(encoding="utf-8"), installed=lambda name: False)
    assert {"bandit", "tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript", "fastapi", "uvicorn", "pyyaml", "httpx"} <= set(names) and "azure-ai-inference" not in names
    print("run_all OK: reads requirements.txt, optional and commented-out packages are never required")


def main() -> int:
    if "--selftest" in sys.argv:
        selftest()
        return 0
    needed = missing_packages((Path(__file__).resolve().parent.parent / "requirements.txt").read_text(encoding="utf-8"))
    if needed:
        print("Some packages the checks need are not installed:  " + ", ".join(needed))
        print("Install them (one time), then run this again:\n\n    pip install -r requirements.txt\n")
        return 2
    failures = []
    for entry in CHECKS:
        module = entry.split()[0]                 # an entry may carry a flag, e.g. "tests.live_decision1 --selftest"
        done = subprocess.run([sys.executable, "-m", *entry.split()], capture_output=True, text=True, encoding="utf-8")
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
