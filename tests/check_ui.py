"""
tests/check_ui.py

Keeps the Phylax UI (clients/ui) honest, in two parts.

1. The demo's data is REAL and must stay real. It was recorded from the actual service (`npm run record-demo`). This check validates every recorded object against the
   OpenAPI contract (capabilities, scans, corrections, verifications), and fails if the recording was made against another contract version than this service speaks:
   the demo would then show something the service no longer says.

2. The UI itself: its linter, its brand check (palette, radii, rem, icons, logo and token files), its tests, and its build, which must come out as ONE html file with
   nothing loaded from the network. It needs Node.js 20+ and the one-time `npm install` in clients/ui; without them part 2 says SKIPPED and why. Part 1 always runs.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "clients" / "ui"
sys.path.insert(0, str(ROOT))
from security_service.version import CONTRACT_VERSION  # noqa: E402


def schema_check() -> str:
    spec = yaml.safe_load((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
    recorded = json.loads((UI / "src" / "api" / "demo" / "recorded.json").read_text(encoding="utf-8"))

    def validate(name: str, value: object, where: str) -> None:
        validator = Draft202012Validator({"components": spec["components"], "$ref": f"#/components/schemas/{name}"})
        problems = sorted(validator.iter_errors(value), key=lambda e: list(e.path))
        assert not problems, f"the recorded {where} does not match the contract's {name}: {problems[0].message} at {list(problems[0].path)}"

    assert recorded["capabilities"]["contract_version"] == CONTRACT_VERSION, (
        f"the demo was recorded against contract {recorded['capabilities']['contract_version']} but the service speaks {CONTRACT_VERSION}: "
        "run `npm run record-demo` in clients/ui")
    validate("Capabilities", recorded["capabilities"], "capabilities")
    for key, scan in recorded["scans"].items():
        validate("Scan", scan, f"scan '{key}'")
    for key, fix in recorded["fixes"].items():
        validate("Fix", fix, f"correction for '{key}'")
    for key, verification in recorded["verifications"].items():
        validate("Verification", verification, f"verification for '{key}'")
    for fix in recorded["fixes"].values():                       # the corrections the demo shows are applicable, and every file in them was part of the scan
        assert fix["applicable"] is True and fix["patches"]
        for patch in fix["patches"]:
            assert patch["path"] in recorded["project"]["files"]
    return f"{len(recorded['scans'])} scans, {len(recorded['fixes'])} sets of corrections and {len(recorded['verifications'])} verifications match contract {CONTRACT_VERSION}"


def run_node(node: str, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run([node, *args], cwd=UI, capture_output=True, text=True, encoding="utf-8", env={**os.environ, "CI": "1", "NO_COLOR": "1"}, timeout=timeout)


def ui_check() -> str:
    node = shutil.which("node")
    if node is None:
        return "UI checks SKIPPED: Node.js is not installed"
    if not (UI / "node_modules" / "vitest" / "vitest.mjs").exists():
        return "UI checks SKIPPED: run `npm install` once in clients/ui first"
    steps = [
        ("lint", ["node_modules/eslint/bin/eslint.js", "."], 120),
        ("brand check", ["scripts/brand-check.mjs"], 60),
        ("tests", ["node_modules/vitest/vitest.mjs", "run"], 280),
        ("build", ["node_modules/vite/bin/vite.js", "build"], 180),
    ]
    tests_line = ""
    for name, args, limit in steps:
        try:
            done = run_node(node, args, limit)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"the UI {name} did not finish in {limit} s. Run it in clients/ui to see where it stalls.")
        out = done.stdout + done.stderr
        assert done.returncode == 0, f"the UI {name} failed:\n{out[-2500:]}"
        if name == "tests":
            passed = re.findall(r"Tests\s+(\d+) passed", out)
            assert passed, "could not read the UI test count:\n" + out[-800:]
            tests_line = f"{passed[-1]} tests"

    page = (UI / "dist" / "index.html").read_text(encoding="utf-8")
    assert len(list((UI / "dist").glob("*.html"))) == 1, "the build is one html file"
    assert not re.search(r"<(script|link)\b[^>]*\b(src|href)=[\"']https?:", page), "the page must not load anything from the network"
    assert "<title>Phylax" in page and "@font-face" in page and "What Phylax found." in page, "the built page is missing its title, its fonts or its headline"
    assert len(page.encode("utf-8")) < 2_000_000, "the single-file build is unexpectedly large"
    return f"lint, brand check, {tests_line}, and a one-file offline build ({len(page) // 1024} KB)"


def run() -> str:
    data = schema_check()
    return f"check_ui OK: {data}; " + ui_check().replace("UI checks SKIPPED", "UI checks SKIPPED")


if __name__ == "__main__":
    try:
        print(run())
    except AssertionError as problem:
        print("UI CHECK FAILED:", problem)
        sys.exit(1)
