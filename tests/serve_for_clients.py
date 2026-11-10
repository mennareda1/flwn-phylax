"""
tests/serve_for_clients.py

Starts a REAL Phylax service (fixes ON, rules for Python, JavaScript and TypeScript) with a stand-in for GPT-6 Astra behind it, prints ONE line of JSON
({"url": ..., "key": ...}) and serves until its standard input is closed. It exists so that client libraries in other languages can be tested against
the real thing over real HTTP: the TypeScript client's end-to-end tests (clients/typescript/test/e2e.test.ts) start it.

    python -m tests.serve_for_clients
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from tests.check_service import REPO_ROOT, free_port
from tests.check_transport import GOOD_KEY, FakeDecision1

CLIENT_KEY = "client-test-key-" + "k" * 24


def keep_reading(stream) -> "collections.deque[str]":
    """The service prints a log line for every request. If nobody reads them the pipe fills (about 4 KB on Windows, 64 KB on Linux) and the service BLOCKS
    on its next log line, so every later request hangs. This helper once did exactly that, and only a Windows run showed it. Read the output for as long as the
    service lives, and keep the last lines for a failure message."""
    tail: collections.deque[str] = collections.deque(maxlen=60)

    def drain() -> None:
        for line in stream:
            tail.append(line)

    threading.Thread(target=drain, daemon=True).start()
    return tail


def shrink_pipe(stream) -> None:
    """Give the pipe Windows' small buffer where the operating system allows it (Linux), so that a reader that falls behind fails HERE too, not only on Windows."""
    try:
        import fcntl

        fcntl.fcntl(stream.fileno(), getattr(fcntl, "F_SETPIPE_SZ", 1031), 4096)
    except (ImportError, OSError, ValueError):
        pass


def main() -> int:
    model = FakeDecision1()
    threading.Thread(target=model.serve_forever, daemon=True).start()
    port = free_port()
    with tempfile.TemporaryDirectory() as folder:
        env_file = Path(folder) / "clients.env"
        env_file.write_text("\n".join([
            f"FOUNDRY_ENDPOINT=http://127.0.0.1:{model.server_address[1]}", f"FOUNDRY_API_KEY={GOOD_KEY}", "CORRECTOR_DEPLOYMENT=gpt-6-astra",
            "SERVICE_FIXES_ENABLED=true", f"SERVICE_PORT={port}", f"SERVICE_API_KEYS=client:scan+fix+read:{CLIENT_KEY}",
            "SERVICE_RATE_LIMIT_PER_MINUTE=1000", "SERVICE_FIX_RATE_LIMIT_PER_MINUTE=1000", "SERVICE_MAX_WAIT_SECONDS=30"]) + "\n", encoding="utf-8")
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("FOUNDRY_", "DECISION1_", "SERVICE_", "CLASSIFIER_", "SCAN_", "CORRECTOR_"))}
        process = subprocess.Popen([sys.executable, "-m", "security_service.api"], cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   env={**clean, "SECURITY_ENV_FILE": str(env_file), "PYTHONPATH": str(REPO_ROOT), "PYTHONUNBUFFERED": "1"})
        base = f"http://127.0.0.1:{port}"
        shrink_pipe(process.stdout)
        output = keep_reading(process.stdout)
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    print(json.dumps({"error": "the service did not start", "output": "".join(output)[-800:]}), flush=True)
                    return 1
                try:
                    with urllib.request.urlopen(base + "/healthz", timeout=2) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.2)
            else:
                print(json.dumps({"error": "the service did not become ready in time"}), flush=True)
                return 1
            print(json.dumps({"url": base, "key": CLIENT_KEY}), flush=True)
            sys.stdin.read()                                     # serve until the test that started us closes our input
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            model.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
