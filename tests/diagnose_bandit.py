"""
tests/diagnose_bandit.py

For a machine where Phylax's Python engine (Bandit) works in a terminal but stalls when the SERVICE starts it. It starts Bandit in the situations that differ and says
how long each took, so the one that stalls is named. Not part of the suite (it can take a couple of minutes if something does stall).

    python -m tests.diagnose_bandit
"""

from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIMIT = 25
SNIPPET = "import os\n\ndef ping(host):\n    os.system('ping ' + host)\n"


def bandit_command(path: Path) -> list[str]:
    return [sys.executable, "-m", "bandit", "-f", "json", "--exit-zero", "-q", "--ignore-nosec", str(path)]


def attempt(label: str, command: list[str], cwd: str, env: dict[str, str] | None = None, stdin=None, hold_stdin_open: bool = False, limit: int = LIMIT) -> None:
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE if hold_stdin_open else stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        out, err = process.communicate(timeout=limit) if not hold_stdin_open else _wait_holding_stdin(process, limit)
        verdict = f"finished in {time.monotonic() - started:4.1f} s   (exit {process.returncode}, {len(out)} bytes of output)"
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        verdict = f"STALLED: still running after {limit} s, stopped"
    print(f"  {label:<78} {verdict}")


def _wait_holding_stdin(process: subprocess.Popen, limit: int) -> tuple[str, str]:
    """Wait for the process while keeping its input pipe OPEN and silent (communicate() would close it, which hides the problem)."""
    process.wait(timeout=limit)
    return (process.stdout.read() if process.stdout else ""), (process.stderr.read() if process.stderr else "")


def main() -> int:
    print(f"Python {sys.version.split()[0]} at {sys.executable}")
    try:
        print(f"bandit {importlib.metadata.version('bandit')}")
    except importlib.metadata.PackageNotFoundError:
        print("bandit is NOT installed for this Python: pip install -r requirements.txt")
        return 1
    suspicious = {name: os.environ[name] for name in ("PYTHONPATH", "PYTHONINSPECT", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE") if name in os.environ}
    print("developer settings in this terminal:", suspicious or "none")
    print(f"each try is stopped after {LIMIT} s\n")
    with tempfile.TemporaryDirectory(prefix="diagnose_bandit_") as folder:
        target = Path(folder) / "snippet.py"
        target.write_text(SNIPPET, encoding="utf-8")
        command = bandit_command(target)
        base = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONINSPECT", "PYTHONSTARTUP")}
        attempt("1. as in a terminal (this terminal's own input)", command, folder, env={**base, "PYTHONUTF8": "1"})
        attempt("2. its input is closed (what Phylax now does)", command, folder, env={**base, "PYTHONUTF8": "1"}, stdin=subprocess.DEVNULL)
        attempt("3. its input is an OPEN pipe that never sends anything", command, folder, env={**base, "PYTHONUTF8": "1"}, hold_stdin_open=True)
        attempt("4. with PYTHONPATH set to this project, as the service had it", command, folder, env={**base, "PYTHONUTF8": "1", "PYTHONPATH": str(ROOT)}, stdin=subprocess.DEVNULL)
        attempt("5. with this project as the working folder", command, str(ROOT), env={**base, "PYTHONUTF8": "1"}, stdin=subprocess.DEVNULL)
        service_like = ("import time; from security_service.adapters.bandit import BanditAnalyzer; t = time.time(); r = BanditAnalyzer().analyze('x = 1\\n', 'python'); "
                        "print('ok:', r.ok, '| seconds:', round(time.time() - t, 1), '| error:', r.error)")
        attempt("6. Phylax's own engine, started from a program whose input is an open pipe (the service)", [sys.executable, "-c", service_like], str(ROOT),
                env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUTF8": "1"}, hold_stdin_open=True, limit=45)
    print("\nSend me this whole output. A line that says STALLED is the cause.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
