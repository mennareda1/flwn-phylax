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
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from security_service.adapters.decision1 import Decision1Classifier
from security_service.core.files import SourceFile
from security_service.core.scan_service import ScanService
from security_service.core.schema import Decision
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
        self.chat_routes = {"openai_v1", "inference"}      # the chat routes this fake "resource" answers; the others give 404


CHAT_PATHS = {"/openai/v1/chat/completions": "openai_v1", "/models/chat/completions": "inference"}


def astra_reply(body: dict, deployment: str) -> dict:
    """What a GPT-6 Astra deployment would answer for the built-in `ping` sample. Some deployment names misbehave on purpose."""
    user = next(m["content"] for m in body["messages"] if m["role"] == "user")
    ids = re.findall(r'<finding_[0-9a-f]+ id="(f\d+)"', user)
    shown = re.search(r'<file_[0-9a-f]+ path="[^"]*">\n(.*)\n</file_[0-9a-f]+>', user, re.S)
    if not shown or '\n    os.system("ping " + host)\n' not in "\n" + shown.group(1) + "\n":
        # what the real GPT-6 Astra answered when the file arrived as a tuple's text instead of source lines
        return {"model": "gpt-6-astra-2026-09-03", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(
            {"edits": [], "unfixed": [{"finding_id": (ids or ["f1"])[0], "reason": "The supplied file is not Python source lines; provide the actual contents."}]})}}],
            "usage": {"prompt_tokens": 510, "completion_tokens": 223, "completion_tokens_details": {"reasoning_tokens": 162}}}
    usage = {"prompt_tokens": 480, "completion_tokens": 2100, "completion_tokens_details": {"reasoning_tokens": 1900}}
    edits = {"edits": [
        {"finding_ids": ids[:1], "old": '    os.system("ping " + host)\n', "new": '    subprocess.run(["ping", host], check=True)\n', "explanation": "Run ping without a shell."},
        {"finding_ids": ids[:1], "old": "import os\n", "new": "import os\nimport subprocess\n", "explanation": "subprocess is needed."}]}
    content, finish = json.dumps(edits), "stop"
    if deployment == "truncated":
        content, finish = "", "length"
    elif deployment == "notjson":
        content = "Sure, I fixed it for you!"
    elif deployment == "badedit":
        edits["edits"][0]["old"] = '    os.system("ping " + target)\n'
        content = json.dumps(edits)
    elif deployment == "swapped":                      # the fix removes the original problem but introduces a different one
        edits["edits"][0]["new"] = '    eval("ping " + host)\n'
        content = json.dumps(edits)
    elif deployment == "unsafe":                       # the fix itself adds a new problem: the re-scan must notice
        edits["edits"][0]["new"] = '    subprocess.run("ping " + host, shell=True)\n'
        content = json.dumps(edits)
    return {"model": "gpt-6-astra-2026-09-03", "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": finish}], "usage": usage}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):          # keep the test output clean
        pass

    def _chat(self, server, headers, body, route):
        """A fake GPT-6 Astra: strict about parameters the way the real model is."""
        if route not in server.chat_routes:
            return self._send(404, {"error": {"code": "NotFound"}})
        if headers.get("api-key") != GOOD_KEY:
            return self._send(401, {"error": {"code": "Unauthorized"}})
        if route == "inference" and headers.get("extra-parameters") != "pass-through":
            return self._send(400, {"error": {"code": "unknown_parameter", "param": "max_completion_tokens"}})
        for refused in ("temperature", "top_p", "logprobs", "max_tokens", "tools"):
            if refused in body:
                return self._send(400, {"error": {"code": "unsupported_parameter", "param": refused}})
        if not isinstance(body.get("max_completion_tokens"), int):
            return self._send(400, {"error": {"code": "missing_parameter", "param": "max_completion_tokens"}})
        if body.get("reasoning_effort") not in ("low", "medium", "high", "xhigh"):
            return self._send(400, {"error": {"code": "unsupported_value", "param": "reasoning_effort"}})
        if body.get("model") == "missing":
            return self._send(404, {"error": {"code": "DeploymentNotFound"}})
        return self._send(200, astra_reply(body, body["model"]))

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
        if self.path.split("?")[0] in CHAT_PATHS:
            return self._chat(server, headers, body, CHAT_PATHS[self.path.split("?")[0]])
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

            # 9b. the SCAN SERVICE with Decision-1 switched on, over real HTTP (this fake server says "yes" to every question)
            def scan_with(overrides, code="x = 1\n"):
                env_on = {"FOUNDRY_ENDPOINT": full_url, "FOUNDRY_API_KEY": GOOD_KEY, "DECISION1_DEPLOYMENT": "decision-1",
                          "CLASSIFIER_ENABLED": "true", **overrides}
                return ScanService.from_settings(Settings.from_env(env_on)).scan([SourceFile("snippet.py", code)])

            before = len(server.requests)
            report = scan_with({})
            asked = server.requests[before:]
            assert len(asked) == 1 and len(asked[0]["body"]["questions"]) == 12                  # one request, twelve questions
            assert report.decision == Decision.REVIEW_REQUIRED and len(report.findings) == 12     # a model that says yes to everything...
            assert all(f.line is None and f.evidence_tier.value == "model_suspicion" for f in report.findings)    # ...asks for review, never blocks
            assert [e.role for e in report.provenance.engines] == ["analyzer", "analyzer", "classifier"]
            assert "microsoft-decision-1" in report.coverage.analyzers_run

            before = len(server.requests)
            scan_with({}, code='password = "hunter22"\nimport os\n')
            assert "hunter22" not in json.dumps(server.requests[before]["body"]) and "<REDACTED_SECRET>" in server.requests[before]["body"]["state"]

            # Decision-1 off (the default): no request is made at all, and the scan is the rules alone
            before = len(server.requests)
            off = ScanService.from_settings(Settings.from_env({"FOUNDRY_ENDPOINT": full_url, "FOUNDRY_API_KEY": GOOD_KEY})).scan([SourceFile("snippet.py", "x = 1\n")])
            assert len(server.requests) == before and off.decision == Decision.PASS and off.findings == []

            # the model service failing: optional (default) = the scan still finishes on the rules and says so; required = scan_failed
            for broken in ({"DECISION1_DEPLOYMENT": "missing"}, {"FOUNDRY_API_KEY": "wrong-key-99999"}):
                down = scan_with(broken)
                assert down.decision == Decision.PASS and down.status == "completed" and down.findings == []
                assert any("Optional engine microsoft-decision-1" in r for r in down.decision_reasons)
                assert list(down.coverage.analyzers_failed) == ["microsoft-decision-1@snippet.py"] and "wrong-key-99999" not in json.dumps(down.to_dict())
                assert scan_with({**broken, "CLASSIFIER_REQUIRED": "true"}).decision == Decision.SCAN_FAILED

            # 9c. the corrector's first-contact tool against a fake GPT-6 Astra: both routes, and every way a deployment can misbehave
            from tests import live_corrector

            def contact(*flags, **env):
                lines: list[str] = []
                base_env = {"FOUNDRY_ENDPOINT": full_url, "FOUNDRY_API_KEY": GOOD_KEY, "CORRECTOR_DEPLOYMENT": "gpt-6-astra"}
                code = live_corrector.main(list(flags), environ={**base_env, **env}, out=lines.append)
                return code, "\n".join(lines)

            before = len(server.requests)
            code, text = contact()
            assert code == 0 and "RESULT on route openai_v1: the fix is usable end to end" in text, text
            assert "CHECK parses: yes" in text and "problem types before ['command_injection'], still present at medium or above: none" in text
            assert '+    subprocess.run(["ping", host], check=True)' in text and "tokens: 480 in, 2100 out (1900 of those were thinking); cost about $0.1098" in text
            assert "answered by gpt-6-astra-2026-09-03" in text and "Put  CORRECTOR_API=openai_v1  in .env." in text and GOOD_KEY not in text
            request = server.requests[before]
            assert request["path"] == "/openai/v1/chat/completions" and request["headers"]["api-key"] == GOOD_KEY
            assert set(request["body"]) == {"model", "messages", "max_completion_tokens", "reasoning_effort"} and request["body"]["reasoning_effort"] == "low"
            assert len(server.requests) == before + 1                                                  # one request, no hidden extras

            server.chat_routes = {"openai_v1"}                                                         # only one route exists on this "resource"
            code, text = contact("--both")
            assert code == 0 and "route inference" in text and "HTTP 404" in text and "the other CORRECTOR_API route" in text
            assert "openai_v1 worked. Put  CORRECTOR_API=openai_v1  in .env." in text
            server.chat_routes = {"inference"}
            code, text = contact()                                                                     # the default route does not exist here: said plainly, exit 1
            assert code == 1 and "HTTP 404" in text and "no route worked" in text
            code, text = contact("--both")
            assert code == 0 and "CORRECTOR_API=inference" in text and "different from your current setting" in text
            assert server.requests[-1]["headers"]["extra-parameters"] == "pass-through"
            server.chat_routes = {"openai_v1", "inference"}

            for deployment, expected in (("truncated", "whole output budget thinking"), ("notjson", "not a JSON object"), ("badedit", "do not fit the file"),
                                         ("unsafe", "NOT usable"), ("swapped", "new at medium or above: ['code_injection']"), ("missing", "CORRECTOR_DEPLOYMENT")):
                code, text = contact("--show-raw", CORRECTOR_DEPLOYMENT=deployment)
                assert code == 1 and expected in text and GOOD_KEY not in text, (deployment, text)
            code, text = contact(CORRECTOR_DEPLOYMENT="notjson")
            assert "what the model said" in text and "Sure, I fixed it for you!" in text                  # when the answer is unusable, it is shown (the sample only)
            code, text = contact("--show-raw")
            assert "raw reply:" in text and '"edits"' in text
            code, text = contact(FOUNDRY_API_KEY="the-wrong-key-12345")
            assert code == 1 and "authentication failed" in text and "the-wrong-key-12345" not in text

            # settings problems stop it before any request is made
            before = len(server.requests)
            for env, expected in (({"CORRECTOR_DEPLOYMENT": ""}, "No deployment"), ({"CORRECTOR_DEPLOYMENT": "GPT-6 Astra"}, "no spaces"), ({"FOUNDRY_API_KEY": ""}, "No API key")):
                code, text = contact(**env)
                assert code == 2 and expected in text and "not ready" in text, (env, text)
            code, text = contact("--sample", "upload")                                                 # the rules cannot see this one, so there is no finding to fix
            assert code == 2 and "nothing to ask the model to fix" in text
            code, text = contact("--sample", "nonsense")
            assert code == 2 and "Unknown sample" in text and len(server.requests) == before
            code, text = contact(CORRECTOR_REASONING_EFFORT="none")                                    # a value Astra refuses is replaced, with a warning
            assert code == 0 and "warning: CORRECTOR_REASONING_EFFORT='none'" in text and server.requests[-1]["body"]["reasoning_effort"] == "low"

            # 9d. the fix tool, end to end: the real rules engine, the real corrector adapter, real HTTP to a fake GPT-6 Astra, real verification
            from security_service import fix as fix_tool
            from security_service.core.patching import apply_unified_diff

            original_text = live_corrector.SAMPLES["ping"].content
            sample_file = Path(folder) / "net.py"
            sample_file.write_text(original_text, encoding="utf-8")
            sample_path = str(sample_file)

            def repair(*flags, **env):
                lines: list[str] = []
                base_env = {"FOUNDRY_ENDPOINT": full_url, "FOUNDRY_API_KEY": GOOD_KEY, "CORRECTOR_DEPLOYMENT": "gpt-6-astra"}
                code = fix_tool.main([sample_path, *flags], environ={**base_env, **env}, out=lines.append)
                return code, "\n".join(lines)

            saved = Path(folder) / "fix.diff"
            before = len(server.requests)
            code, text = repair("--save-patch", str(saved))
            assert code == 0, text
            assert "scan: block" in text and "command_injection" in text and "VERIFICATION: passed" in text and "RESULT: a verified fix was produced" in text
            assert "model use: 1 request(s), 480 tokens in, 2100 out (1900 thinking)" in text and GOOD_KEY not in text
            assert sample_file.read_text(encoding="utf-8") == original_text                                   # the user's file is never touched
            assert apply_unified_diff(original_text, saved.read_text(encoding="utf-8"), sample_path.replace("\\", "/")) == \
                original_text.replace('    os.system("ping " + host)\n', '    subprocess.run(["ping", host], check=True)\n').replace("import os\n", "import os\nimport subprocess\n")
            asked = server.requests[before:]
            assert len(asked) == 1 and asked[0]["path"] == "/openai/v1/chat/completions"                       # one model request; rules only, so Decision-1 was not called
            assert "<REDACTED_SECRET>" not in asked[0]["body"]["messages"][1]["content"] and original_text in asked[0]["body"]["messages"][1]["content"]

            for deployment, expected in (("unsafe", "Still present after the change: f1 (command_injection"), ("swapped", "new finding n1: code_injection"),
                                         ("badedit", "BadProposal"), ("truncated", "whole output budget"), ("notjson", "not a JSON object"),
                                         ("missing", "CORRECTOR_DEPLOYMENT")):
                refused_patch = Path(folder) / f"{deployment}.diff"
                code, text = repair("--save-patch", str(refused_patch), CORRECTOR_DEPLOYMENT=deployment)
                assert code == 3 and expected in text and "RESULT: no verified fix" in text, (deployment, text)
                assert not refused_patch.exists() and sample_file.read_text(encoding="utf-8") == original_text, deployment      # nothing saved, nothing changed
            code, text = repair(FOUNDRY_API_KEY="the-wrong-key-12345")
            assert code == 3 and "authentication failed" in text and "the-wrong-key-12345" not in text
            assert repair("--finding", "f9")[0] == 4 and repair(CORRECTOR_DEPLOYMENT="")[0] == 4              # a bad id, and a missing setting, never reach the model

            # 10. the program itself: `python -m tests.live_decision1` configured only by a .env file
            clean = {k: v for k, v in os.environ.items() if k not in VARIABLES}
            done = subprocess.run([sys.executable, "-m", "tests.live_decision1"], cwd=REPO_ROOT, capture_output=True, text=True,
                                  encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path)}, timeout=60)
            assert done.returncode == 0 and "parsed OK" in done.stdout and GOOD_KEY not in done.stdout + done.stderr, done.stdout + done.stderr
            assert "settings from" in done.stdout

            # 11. the evaluation program, end to end against the fake server, run in a temp folder so nothing is written into the repo
            work = Path(folder) / "work"
            work.mkdir()
            eval_env = {**clean, "SECURITY_ENV_FILE": str(env_path), "PYTHONPATH": str(REPO_ROOT)}

            def evaluation(*flags):
                return subprocess.run([sys.executable, "-m", "benchmark.classifier_eval", *flags], cwd=work, capture_output=True,
                                      text=True, encoding="utf-8", env=eval_env, timeout=240)

            before = len(server.requests)
            smoke = evaluation("--limit", "3")                                                   # development smoke test
            assert smoke.returncode == 0, smoke.stdout + smoke.stderr
            report_file, json_file = work / "classifier_eval_report.txt", work / "classifier_eval_results.json"
            assert report_file.is_file() and json_file.is_file()
            report_text = report_file.read_text(encoding="utf-8")
            assert "SMOKE TEST" in report_text and "DEVELOPMENT RUN" in report_text and "RAW SCORES" in report_text
            assert GOOD_KEY not in smoke.stdout + smoke.stderr + report_text + json_file.read_text(encoding="utf-8")
            sent = server.requests[before:]
            assert len(sent) >= 3, len(sent)
            first = sent[0]["body"]
            assert len(first["questions"]) == 12 and all(q["type"] == "noul" and q["criteria"]["true"] for q in first["questions"].values()), list(first["questions"])
            assert "hardcoded_credentials" not in first["questions"] and "worst_problem" not in first["questions"]   # no secrets question, no verdict question
            assert any(r["body"]["state"].startswith("# Security review") for r in sent)        # the injection variants were sent
            assert json.loads(json_file.read_text(encoding="utf-8"))["gate"]["final"] is False   # a smoke test is never a final verdict

            # the full held-out run: one request per case plus the injection variants, and a FINAL verdict
            before = len(server.requests)
            final = evaluation("--heldout")
            assert final.returncode == 0, final.stdout + final.stderr
            final_text = report_file.read_text(encoding="utf-8")
            assert "HELD-OUT RUN: the final verdict" in final_text and "THE GATE (version 2" in final_text and "VERDICT (FINAL, held-out set)" in final_text
            from benchmark.cases_heldout import HELDOUT_CASES, fingerprint
            assert fingerprint() in final_text and GOOD_KEY not in final.stdout + final_text
            assert len(server.requests) - before == len(HELDOUT_CASES) + 2 * sum(c["kind"] == "vulnerable" for c in HELDOUT_CASES)
            assert json.loads(json_file.read_text(encoding="utf-8"))["gate"]["final"] is True

            # a partial held-out run is refused before any request is made
            before = len(server.requests)
            refused = evaluation("--heldout", "--limit", "3")
            assert refused.returncode == 2 and "peeking" in refused.stdout and len(server.requests) == before

            # 10b. the scan command, as a program, with Decision-1 switched on from the terminal (this fake server says yes to everything)
            target = Path(folder) / "app.py"
            target.write_text("x = 1\n", encoding="utf-8")
            scan_cli = subprocess.run([sys.executable, "-m", "security_service.scan", str(target)], cwd=REPO_ROOT, capture_output=True, text=True,
                                      encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path), "CLASSIFIER_ENABLED": "true"}, timeout=60)
            assert scan_cli.returncode == 1, scan_cli.stdout + scan_cli.stderr                  # review_required: model findings never block
            assert "decision: review_required" in scan_cli.stdout and "model_suspicion" in scan_cli.stdout and "microsoft-decision-1" in scan_cli.stdout
            assert GOOD_KEY not in scan_cli.stdout + scan_cli.stderr
            rules_only = subprocess.run([sys.executable, "-m", "security_service.scan", str(target)], cwd=REPO_ROOT, capture_output=True, text=True,
                                        encoding="utf-8", env={**clean, "SECURITY_ENV_FILE": str(env_path)}, timeout=60)
            assert rules_only.returncode == 0 and "decision: pass" in rules_only.stdout and "microsoft-decision-1" not in rules_only.stdout   # off by default

            # 10c. the corrector tool as a program, from a .env file
            corrector_env = Path(folder) / "corrector.env"
            corrector_env.write_text(f"FOUNDRY_ENDPOINT={full_url}\nFOUNDRY_API_KEY={GOOD_KEY}\nCORRECTOR_DEPLOYMENT=gpt-6-astra\n", encoding="utf-8")
            as_program = subprocess.run([sys.executable, "-m", "tests.live_corrector"], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
                                        env={**clean, "SECURITY_ENV_FILE": str(corrector_env)}, timeout=120)
            assert as_program.returncode == 0 and "the fix is usable end to end" in as_program.stdout and GOOD_KEY not in as_program.stdout + as_program.stderr, as_program.stdout + as_program.stderr

            # 10d. the fix tool as a program, from a .env file
            fixed_by_program = subprocess.run([sys.executable, "-m", "security_service.fix", sample_path], cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
                                              env={**clean, "SECURITY_ENV_FILE": str(corrector_env)}, timeout=120)
            assert fixed_by_program.returncode == 0 and "VERIFICATION: passed" in fixed_by_program.stdout and GOOD_KEY not in fixed_by_program.stdout + fixed_by_program.stderr, fixed_by_program.stdout + fixed_by_program.stderr

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
