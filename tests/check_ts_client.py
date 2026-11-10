"""
tests/check_ts_client.py

Runs the TypeScript client's own tests (clients/typescript) as one check of this suite. It needs Node.js 20+ and the one-time `npm install` in
clients/typescript; without them it says SKIPPED and why, and passes nothing silently. The client's end-to-end tests start the real service
(tests/serve_for_clients.py), so this also proves the TypeScript client and the Python service agree.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CLIENT = Path(__file__).resolve().parent.parent / "clients" / "typescript"


def run() -> str:
    node = shutil.which("node")
    if node is None:
        return "check_ts_client SKIPPED: Node.js is not installed (install Node 20+ to run the TypeScript client's tests)"
    tsc = CLIENT / "node_modules" / "typescript" / "bin" / "tsc"
    if not tsc.exists():
        return "check_ts_client SKIPPED: run `npm install` once in clients/typescript first (it installs the TypeScript compiler)"
    env = {**os.environ, "PHYLAX_PYTHON": sys.executable}
    built = subprocess.run([node, str(tsc), "-p", "tsconfig.json"], cwd=CLIENT, capture_output=True, text=True, encoding="utf-8", env=env, timeout=240)
    assert built.returncode == 0, "the TypeScript client does not compile:\n" + (built.stdout + built.stderr)[-1500:]
    try:
        tests = subprocess.run([node, "scripts/run-tests.mjs"], cwd=CLIENT, capture_output=True, text=True, encoding="utf-8", env=env, timeout=330)
    except subprocess.TimeoutExpired as stalled:
        partial = (stalled.stdout.decode("utf-8", "replace") if isinstance(stalled.stdout, bytes) else (stalled.stdout or ""))[-1500:]
        raise AssertionError("the TypeScript tests did not finish in time. Run `node scripts/run-tests.mjs` in clients/typescript to see which file stalls.\n" + partial)
    out = tests.stdout + tests.stderr
    last = lambda name, default: int((re.findall(rf"# {name} (\d+)", out) or [str(default)])[-1])          # the runner prints one aggregate summary, last
    passed, failed, skipped = last("pass", 0), last("fail", 1), last("skipped", 0)
    assert tests.returncode == 0 and failed == 0 and passed > 0, "the TypeScript client's tests failed:\n" + out[-3000:]
    note = f" ({skipped} skipped: Python or its packages were not available to the end-to-end tests)" if skipped else ""
    return f"check_ts_client OK: {passed} TypeScript tests pass, including the real change mechanism of Oqelira and the real service{note}"


if __name__ == "__main__":
    try:
        print(run())
    except AssertionError as problem:
        print("TYPESCRIPT CLIENT CHECK FAILED:", problem)
        sys.exit(1)
