"""
tests/check_transport.py

The REAL network code, end to end, with no internet and no key. It starts a fake Decision-1 server on
this machine (127.0.0.1, a free port) and drives the adapter through its real HTTP path (urllib, not a
stand-in), the .env loading, and the live-test script itself.

What it proves that the other checks cannot:
  - the exact URL, headers and JSON that reach the server, including with a pasted full endpoint URL;
  - 401 / 404 / 429 / timeouts / refused connections behave as documented, over a real socket;
  - a .env file (with Windows line endings and a byte-order mark) really configures a real call;
  - `python -m tests.live_decision1` works as a program, and stops with a clear message when unconfigured.

If this machine does not allow local sockets, the check says so and passes without running.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from security_service.adapters.decision1 import Decision1Classifier
from security_service.config import REPO_ROOT, VARIABLES, Settings, load_env_file
from security_service.ports.classifier import (
    ClassifierRejected,
    ClassifierUnavailable,
    Question,
    validate_result,
)
from tests.live_decision1 import run as live_run

GOOD_KEY = "good-key-0123456789"
GOOD_TOKEN = "good-token-abc"
PATH = "/providers/microsoft/v1/systemone"


def reply_for(body: dict) -> dict:
    answers = {}
    for name, question in body["questions"].items():
        if question["type"] == "noul":
            answers[name] = {"type": "noul", "noul": 0.91}
        else:
            options = list(question["criteria"])
            share = 0.3 / max(1, len(options) - 1)
            answers[name] = {"type": "choice", "choice": options[0], "confidence": 0.77,
                             "probabilities": {o: (0.7 if o == options[0] else share) for o in options}}
    return {"model": "microsoft-decision-1", "answers": answers,
            "usage": {"input_tokens": len(str(body.get("state", "")).split()), "output_tokens": len(answers)}}


class FakeDecision1(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass   # a client that hangs up on purpose (the timeout scenario) is expected; do not print a stack trace for it

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests: list[dict] = []
        self.flaky_left = 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):          # keep the test output clean
        pass

    def _send(self, status: int, payload: dict, extra: dict | None = None) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        server: FakeDecision1 = self.server  # type: ignore[assignment]
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        headers = {k.lower(): v for k, v in self.headers.items()}
        body = json.loads(raw) if raw else {}
        server.requests.append({"path": self.path, "headers": headers, "body": body})
        if self.path != PATH:
            return self._send(404, {"error": {"code": "NotFound"}})
        if headers.get("api-key") != GOOD_KEY and headers.get("authorization") != f"Bearer {GOOD_TOKEN}":
            return self._send(401, {"error": {"code": "Unauthorized"}})
        model = body.get("model")
        if model == "missing":
            return self._send(404, {"error": {"code": "DeploymentNotFound"}})
        if model == "flaky" and server.flaky_left > 0:
            server.flaky_left -= 1
            return self._send(429, {"error": {"code": "TooManyRequests"}}, {"Retry-After": "0"})
        if model == "slow":
            time.sleep(3.0)
        return self._send(200, reply_for(body))


def run() -> None:
    try:
        server = FakeDecision1()
    except OSError as problem:
        print(f"check_transport SKIPPED: this machine does not allow local sockets ({problem})")
        return
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    host_url = f"http://127.0.0.1:{port}"
    full_url = host_url + PATH
    questions = [
        Question("secret", "yes_no", "Does the code contain a hardcoded password?"),
        Question("worst", "choice", "Which problem is most serious?", {"hardcoded_secret": "a secret", "command_injection": "a shell", "none": "nothing", "cannot_tell": "unclear"}),
    ]
    code = 'DB_PASSWORD = "SuperSecret123!"\nimport os\nos.system("ping " + host)\n'

    def classifier(endpoint=full_url, key=GOOD_KEY, deployment="decision-1", **kw):
        return Decision1Classifier(deployment=deployment, endpoint=endpoint, api_key=key, **kw)   # default transport: real urllib

    def last():
        return server.requests[-1]

    try:
        # 1. a real call with the full URL: right path (not doubled), right headers, masked body, parsed reply
        result = classifier().classify(code, questions)
        validate_result(questions, result)
        seen = last()
        assert seen["path"] == PATH, seen["path"]
        assert seen["headers"]["api-key"] == GOOD_KEY and seen["headers"]["content-type"] == "application/json"
        assert seen["body"]["model"] == "decision-1" and set(seen["body"]["questions"]) == {"secret", "worst"}
        assert "SuperSecret123" not in json.dumps(seen["body"]) and "<REDACTED_SECRET>" in seen["body"]["state"]
        assert result.answers["secret"].probability == 0.91 and result.answers["worst"].choice == "hardcoded_secret"
        assert result.model == "Microsoft-Decision-1@1"

        # 2. the host alone gives the identical request
        count = len(server.requests)
        classifier(endpoint=host_url).classify("x = 1", questions)
        assert len(server.requests) == count + 1 and last()["path"] == PATH

        # 3. Entra-style bearer token over the real socket
        Decision1Classifier(endpoint=host_url, token_provider=lambda: GOOD_TOKEN).classify("x = 1", questions)
        assert last()["headers"]["authorization"] == f"Bearer {GOOD_TOKEN}" and "api-key" not in last()["headers"]

        # 4. wrong key: rejected at once, not retried, and the message names the cause but not the key
        count = len(server.requests)
        try:
            classifier(key="wrong-key-99999").classify(code, questions)
            raise AssertionError("expected ClassifierRejected")
        except ClassifierRejected as problem:
            assert "HTTP 401" in str(problem) and "wrong-key-99999" not in str(problem) and GOOD_KEY not in str(problem)
        assert len(server.requests) == count + 1

        # 5. wrong deployment name: 404 with the provider's code and our hint, no retry
        count = len(server.requests)
        try:
            classifier(deployment="missing").classify(code, questions)
            raise AssertionError("expected ClassifierRejected")
        except ClassifierRejected as problem:
            assert "HTTP 404" in str(problem) and "DeploymentNotFound" in str(problem) and "SuperSecret123" not in str(problem)
        assert len(server.requests) == count + 1

        # 6. the old bug: an endpoint with the path pasted twice used to produce a doubled path and a 404; it is cleaned now
        count = len(server.requests)
        classifier(endpoint=full_url + PATH).classify("x = 1", questions)
        assert len(server.requests) == count + 1 and last()["path"] == PATH, last()["path"]

        # 7. rate limiting: two 429s then success, honoring Retry-After; then exhaustion
        server.flaky_left = 2
        count = len(server.requests)
        classifier(deployment="flaky").classify("x = 1", questions)
        assert len(server.requests) == count + 3
        server.flaky_left = 9
        try:
            classifier(deployment="flaky", max_attempts=2).classify("x = 1", questions)
            raise AssertionError("expected ClassifierUnavailable")
        except ClassifierUnavailable as problem:
            assert "rate limit" in str(problem) and "2 attempts" in str(problem)
        server.flaky_left = 0

        # 8. a timeout and a refused connection are network errors, never a hang or a crash
        started = time.monotonic()
        try:
            classifier(deployment="slow", timeout=0.3, max_attempts=1).classify("x = 1", questions)
            raise AssertionError("expected ClassifierUnavailable")
        except ClassifierUnavailable as problem:
            assert "network error" in str(problem)
        assert time.monotonic() - started < 2.0     # returned at the 0.3 s timeout, not after the server's 3 s stall
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        dead_port = closed.getsockname()[1]
        closed.close()
        try:
            classifier(endpoint=f"http://127.0.0.1:{dead_port}", max_attempts=1).classify("x = 1", questions)
            raise AssertionError("expected ClassifierUnavailable")
        except ClassifierUnavailable as problem:
            assert "network error" in str(problem)

        # 9. a .env file (Windows line endings, byte-order mark, comments) configures a real call end to end
        with tempfile.TemporaryDirectory() as folder:
            env_path = Path(folder) / ".env"
            # the byte-order mark sits directly before the FIRST SETTING, exactly as Windows Notepad writes it
            env_path.write_bytes(("\ufeffFOUNDRY_ENDPOINT=" + full_url + "\r\n# Decision-1\r\nFOUNDRY_API_KEY=" + GOOD_KEY
                                  + "   # the key\r\nDECISION1_DEPLOYMENT=decision-1\r\n").encode("utf-8"))
            env: dict[str, str] = {}
            assert load_env_file(env_path, environ=env) == env_path
            settings = Settings.from_env(env)
            assert settings.problems() == [] and settings.decision1_endpoint == host_url
            lines: list[str] = []
            assert live_run(Decision1Classifier.from_settings(settings), lines.append) == 0
            text = "\n".join(lines)
            assert "parsed OK" in text and f"calling: {full_url}" in text and GOOD_KEY not in text and "SuperSecret123" not in text
            assert text.count("/providers/microsoft/v1/systemone") == 1          # the URL is shown once, not doubled

            # 10. the program itself: `python -m tests.live_decision1` configured only by a .env file
            clean = {k: v for k, v in os.environ.items() if k not in VARIABLES}
            done = subprocess.run([sys.executable, "-m", "tests.live_decision1"], cwd=REPO_ROOT, capture_output=True, text=True,
                                  encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path)}, timeout=60)
            assert done.returncode == 0 and "parsed OK" in done.stdout and GOOD_KEY not in done.stdout + done.stderr, done.stdout + done.stderr
            assert "settings from" in done.stdout

            # 11. the evaluation program, end to end against the fake server: settings, 14-question requests with criteria,
            # injection variants, analysis, and both result files (run in a temp folder, so nothing is written into the repo)
            work = Path(folder) / "work"
            work.mkdir()
            before = len(server.requests)
            evaluation = subprocess.run([sys.executable, "-m", "benchmark.classifier_eval", "--limit", "3"], cwd=work, capture_output=True,
                                        text=True, encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path), "PYTHONPATH": str(REPO_ROOT)}, timeout=180)
            assert evaluation.returncode == 0, evaluation.stdout + evaluation.stderr
            report_file, json_file = work / "classifier_eval_report.txt", work / "classifier_eval_results.json"
            assert report_file.is_file() and json_file.is_file()
            report_text = report_file.read_text(encoding="utf-8")
            assert "SMOKE TEST" in report_text and "VERDICT" in report_text and "RAW SCORES" in report_text
            assert GOOD_KEY not in evaluation.stdout + evaluation.stderr + report_text + json_file.read_text(encoding="utf-8")
            sent = server.requests[before:]
            assert len(sent) >= 3, len(sent)
            first = sent[0]["body"]
            assert len(first["questions"]) == 14 and first["questions"]["command_injection"]["criteria"]["true"], list(first["questions"])
            assert first["questions"]["worst_problem"]["type"] == "choice" and "cannot_tell" in first["questions"]["worst_problem"]["criteria"]
            assert any(r["body"]["state"].startswith("# Security review") for r in sent)        # the injection variants were sent
            assert json.loads(json_file.read_text(encoding="utf-8"))["gate"]["verdict"] == "NOT DECIDED"   # three cases can never decide the gate

            # ...a variable in the terminal beats the file: a wrong key in the terminal must fail, even though the file has the right one
            override = subprocess.run([sys.executable, "-m", "tests.live_decision1"], cwd=REPO_ROOT, capture_output=True, text=True,
                                      encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path), "FOUNDRY_API_KEY": "terminal-wrong-key-123"}, timeout=60)
            assert override.returncode == 1 and "HTTP 401" in override.stdout, override.stdout + override.stderr
            assert "terminal-wrong-key-123" not in override.stdout + override.stderr and GOOD_KEY not in override.stdout + override.stderr

            # ...and with no configuration at all it stops with a clear message instead of failing mysteriously
            nothing = subprocess.run([sys.executable, "-m", "tests.live_decision1"], cwd=REPO_ROOT, capture_output=True, text=True,
                                     encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(Path(folder) / "missing.env")}, timeout=60)
            assert nothing.returncode == 2 and "Cannot start" in nothing.stdout and "No endpoint" in nothing.stdout and "No API key" in nothing.stdout

            # ...and the config check agrees, without any network call
            checked = subprocess.run([sys.executable, "-m", "security_service.config", "--env-file", str(env_path)], cwd=REPO_ROOT, capture_output=True,
                                     text=True, encoding="utf-8", env=clean, timeout=60)
            # the exit code is 2 only when the committed .env.example holds real values (reported by its own check);
            # this test is about the settings in the .env above, so it must not depend on the template's state
            assert checked.returncode == (2 if "WARNING" in checked.stdout else 0), checked.stdout
            assert "Problems: none" in checked.stdout and GOOD_KEY not in checked.stdout
            assert f"URL it calls ... {full_url}" in checked.stdout
    finally:
        server.shutdown()
        server.server_close()

    print("check_transport OK: real HTTP end to end (URL, headers, masking, 401/404/429/timeout/refused), .env with CRLF+BOM, live test as a program")


if __name__ == "__main__":
    run()
