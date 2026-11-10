"""
tests/check_deploy.py

Keeps the deployment honest. It cannot build the container or run Azure, so it checks what can be checked without them:

  - the Dockerfile: a pinned base, the pinned packages, a non-root user, a health check, no secret and no .env baked in, the service bound to the network;
  - requirements-runtime.txt and constraints-runtime.txt agree, hold no test tool, and the service's own code imports none;
  - the two workflows: valid, actions pinned, the smallest permissions, and the image is smoke-tested BEFORE it is published;
  - the production settings file: only settings the service knows, no real secret, and loaded by the real config it gives the wanted production setup
    (corrections on, Decision-1 on for Python only), and the real `--check` accepts it;
  - deploy/smoke.py, run against a real local service: it passes, it fails on a wrong key, a missing key, an unreachable address, and refuses plain http to a remote host,
    and it never prints the key.
"""

from __future__ import annotations

import ast
import http.server
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from security_service.config import VARIABLES, Settings  # noqa: E402

TEST_ONLY = {"httpx", "jsonschema", "openapi-spec-validator", "openapi_spec_validator", "pytest"}


def names(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            found.append(re.split(r"[<>=!~\[;\s]", line, maxsplit=1)[0].lower().replace("_", "-"))
    return found


def check_dockerfile() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    text = text.replace("\\\n", " ")                                    # a Dockerfile instruction can continue on the next line: look at it as ONE instruction
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    joined = "\n".join(lines)
    assert re.search(r"^FROM python:3\.12-slim", joined, re.M) and ":latest" not in joined, "the base image is pinned to a Python version, never :latest"
    assert "-c constraints-runtime.txt" in joined and "-r requirements-runtime.txt" in joined, "packages are installed at the pinned versions"
    assert re.search(r"^USER (?!root)\S+", joined, re.M) and "USER root" not in joined, "the container runs as an ordinary user"
    assert joined.index("useradd") < joined.index("USER ") , "the user is created before it is used"
    assert re.search(r"^HEALTHCHECK .*healthz", joined, re.M | re.S), "there is a health check on /healthz"
    assert "EXPOSE 8080" in joined and "SERVICE_HOST=0.0.0.0" in joined, "the service is reachable from outside the container"
    assert lines[-1].startswith("CMD") and "security_service.api" in lines[-1], "it starts the service"
    assert not re.search(r"^COPY\s+(\.|\*)\s", joined, re.M), "only what the service needs is copied (never the whole folder)"
    assert not re.search(r"COPY[^\n]*\.env", joined) and ".env" not in re.sub(r"requirements|constraints", "", " ".join(l for l in lines if l.startswith("COPY"))), "no .env is copied in"
    for line in lines:
        if line.startswith(("ENV", "ARG")):
            assert not re.search(r"(KEYS?|SECRETS?|TOKENS?|PASSWORDS?)\s*=\s*\S", line, re.I), f"a secret is baked into the image: {line.split('=')[0]}"
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for needed in (".git", ".env", "**/node_modules", "tests", "clients"):
        assert needed in ignore, f".dockerignore must keep {needed} out of the image"


def check_requirements() -> None:
    runtime = names((ROOT / "requirements-runtime.txt").read_text(encoding="utf-8"))
    everything = names((ROOT / "requirements.txt").read_text(encoding="utf-8"))
    pins = (ROOT / "constraints-runtime.txt").read_text(encoding="utf-8")
    pinned = {m.group(1).lower().replace("_", "-"): m.group(2) for m in re.finditer(r"^([A-Za-z0-9_.\-]+)==(\S+)$", pins, re.M)}
    assert {"bandit", "tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript", "tree-sitter-java", "fastapi", "uvicorn"} <= set(runtime)
    assert set(runtime) <= set(everything), "everything the container installs is also in requirements.txt"
    assert set(runtime) <= set(pinned), f"every runtime package is pinned exactly: missing {set(runtime) - set(pinned)}"
    assert not (TEST_ONLY & set(pinned)) and not (TEST_ONLY & set(runtime)), "no test tool is in the image"
    assert len(pinned) >= 20 and all(re.fullmatch(r"[0-9][\w.\-+]*", v) for v in pinned.values())
    # the service's own code must not need a test tool when it starts (imports inside demo functions do not count)
    for path in (ROOT / "security_service").rglob("*.py"):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            for module in modules:
                assert module.split(".")[0].lower().replace("_", "-") not in TEST_ONLY, f"{path.relative_to(ROOT)} imports {module} at the top level, but the image does not have it"


def check_workflows() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    publish = yaml.safe_load((ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    assert ci["permissions"] == {"contents": "read"}, "CI can only read"
    assert publish["permissions"] == {"contents": "read", "packages": "write"}, "publishing may write packages and nothing else"
    for name, workflow in (("ci", ci), ("publish", publish)):
        triggers = workflow.get("on", workflow.get(True))
        assert "pull_request_target" not in triggers, f"{name}: never run untrusted pull requests with write access"
        for job in workflow["jobs"].values():
            assert job.get("timeout-minutes"), f"{name}: every job has a time limit"
            for step in job["steps"]:
                if "uses" in step:
                    assert re.search(r"@v\d+$", step["uses"]), f"{name}: {step['uses']} must be pinned to a version"
    assert "v*" in publish[True if True in publish else "on"]["push"]["tags"], "publishing is triggered by a version tag"
    steps = publish["jobs"]["image"]["steps"]
    labels = [s.get("name", s.get("uses", "")) for s in steps]
    smoke = next(i for i, s in enumerate(steps) if "smoke.py" in s.get("run", ""))
    push = next(i for i, s in enumerate(steps) if str(s.get("with", {}).get("push", "")).lower() == "true")
    login = next(i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("docker/login-action"))
    assert smoke < login < push, f"the image is smoke-tested BEFORE anything is published: {labels}"
    assert "load" in steps[next(i for i, s in enumerate(steps) if s.get("with", {}).get("load"))]["with"], "the candidate image is loaded so it can be started"
    assert any("run_all" in s.get("run", "") for s in ci["jobs"]["test"]["steps"]), "CI runs the whole suite"
    assert any("npm ci" in s.get("run", "") for s in ci["jobs"]["test"]["steps"]), "CI installs the TypeScript packages from the lockfile"
    assert "::add-mask::" in "\n".join(s.get("run", "") for s in steps), "the throwaway key used to test the image is masked in the logs"


def environment_file() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / "deploy/azure/production.env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            name, _, value = line.partition("=")
            values[name] = value
    return values


def check_production_settings() -> None:
    values = environment_file()
    assert set(values) <= set(VARIABLES), f"the production file names a setting the service does not know: {set(values) - set(VARIABLES)}"
    for secret in ("SERVICE_API_KEYS", "FOUNDRY_API_KEY"):
        assert "REPLACE" in values[secret], f"{secret} is a placeholder, never a real value"
    assert not re.search(r"[A-Za-z0-9_\-]{32,}", " ".join(v for k, v in values.items() if "KEY" in k and "REPLACE" not in v)), "no real-looking secret is in the file"
    # with real-looking values in place of the placeholders, the REAL configuration reads it as the wanted production setup
    real = {**values, "SERVICE_API_KEYS": "flwn-ai:scan+fix+read:" + "k" * 43, "FOUNDRY_API_KEY": "f" * 40}
    settings = Settings.from_env(real)
    assert settings.warnings == (), f"the production file produces warnings: {settings.warnings}"
    assert settings.classifier_enabled is True and settings.classifier_languages == ("python",), "Decision-1 is on, for Python only"
    assert settings.service_fixes_enabled is True and settings.service_host == "0.0.0.0" and settings.service_port == 8080
    assert settings.service_fix_rate_limit_per_minute <= 10, "corrections, which cost money, have a strict limit"
    environment = {k: v for k, v in os.environ.items() if k not in VARIABLES}
    shown = subprocess.run([sys.executable, "-m", "security_service.api", "--check"], cwd=ROOT, env={**environment, **real, "PYTHONPATH": str(ROOT)}, capture_output=True, text=True, timeout=60)
    assert shown.returncode == 0, "the real `--check` accepts the production settings:\n" + shown.stdout[-800:] + shown.stderr[-400:]
    assert "k" * 43 not in shown.stdout + shown.stderr and "f" * 40 not in shown.stdout + shown.stderr, "--check never shows a key"
    assert re.search(r"Fixes: ON", shown.stdout) and "python" in shown.stdout and "javascript" not in re.search(r"Decision-1[^\n]*", shown.stdout).group(0), shown.stdout[-900:]
    guide = (ROOT / "deploy/azure/README.md").read_text(encoding="utf-8")
    for promise in ("never changes a file", "ONE", "ghcr.io/mennareda1/flwn-phylax", "smoke.py", "--min-replicas 1 --max-replicas 1"):
        assert promise in guide, f"the Azure guide must say: {promise}"
    assert "REPLACE" not in guide and not re.search(r"[A-Za-z0-9_\-]{40,}", re.sub(r"https?://\S+|`[^`]*`", "", guide)), "the guide holds no secret"


def run_smoke(args: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "deploy/smoke.py", *args], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=180)


def check_smoke() -> None:
    log_file = Path(tempfile.mkdtemp(prefix="phylax_helper_")) / "service.log"
    helper = subprocess.Popen([sys.executable, "-m", "tests.serve_for_clients"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                              env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1", "PHYLAX_HELPER_LOG": str(log_file)})
    failure: AssertionError | None = None
    try:
        info = json.loads(helper.stdout.readline())
        url, key = info["url"], info["key"]
        base = {k: v for k, v in os.environ.items() if k != "PHYLAX_API_KEY"}
        good = run_smoke(["--url", url, "--fix"], {**base, "PHYLAX_API_KEY": key})
        assert good.returncode == 0 and "FAIL" not in good.stdout, good.stdout[-1500:]
        for expected in ("NO key is refused", "WRONG key is refused", "Python snippet is BLOCKED", "JavaScript snippet is BLOCKED", "comes back verified", "file hashes"):
            assert f"PASS  " in good.stdout and expected in good.stdout, f"missing check: {expected}\n{good.stdout}"
        assert key not in good.stdout + good.stderr, "the key is never printed"
        plain = run_smoke(["--url", url], {**base, "PHYLAX_API_KEY": key})
        assert plain.returncode == 0 and "comes back verified" not in plain.stdout, "without --fix no correction is requested (it would cost a model call)"
        wrong = run_smoke(["--url", url], {**base, "PHYLAX_API_KEY": "w" * 43})
        assert wrong.returncode == 1 and "FAIL  your key is accepted" in wrong.stdout and "w" * 43 not in wrong.stdout + wrong.stderr
        assert run_smoke(["--url", url], base).returncode == 2, "no key at all: it says so and does not run"
        assert run_smoke(["--url", url, "--key-env", "SOMETHING_ELSE"], {**base, "PHYLAX_API_KEY": key}).returncode == 2
        down = run_smoke(["--url", "http://127.0.0.1:9"], {**base, "PHYLAX_API_KEY": key})
        assert down.returncode == 1 and "did not answer" in down.stdout and key not in down.stdout
        remote = run_smoke(["--url", "http://phylax.example.com"], {**base, "PHYLAX_API_KEY": key})
        assert remote.returncode == 2 and "plain http" in remote.stdout, "the key is never sent over plain http to a remote address"
        assert run_smoke(["--url", "phylax.example.com"], {**base, "PHYLAX_API_KEY": key}).returncode == 2
        assert run_smoke(["--url", url + "/"], {**base, "PHYLAX_API_KEY": key}).returncode == 0, "a trailing slash is fine"
    except AssertionError as problem:
        failure = problem
    finally:
        try:
            helper.stdin.close()
            helper.wait(timeout=30)
        except Exception:
            helper.kill()
    if failure is not None:                                              # show the service's own account of what happened, so a hidden cause cannot stay hidden
        tail = log_file.read_text(encoding="utf-8", errors="replace")[-2500:] if log_file.exists() else "(no log was kept)"
        raise AssertionError(f"{failure}\n--- the service's own log, last lines:\n{tail}")


def load_smoke():
    spec = importlib.util.spec_from_file_location("phylax_smoke", ROOT / "deploy" / "smoke.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PretendPhylax:
    """A Phylax that answers from a script, so the smoke test can be shown a slow start, a service that never gets ready, or a busy one.
    `routes` maps (method, path) to a list of (status, body); the last answer repeats. Anything under /v1 needs the right key."""

    def __init__(self, key: str, routes: dict):
        self.key, self.routes, self.calls = key, routes, []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def respond(self, method: str) -> None:
                owner.calls.append((method, self.path))
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path.startswith("/v1") and self.headers.get("Authorization") != f"Bearer {owner.key}":
                    status, body = 401, {"title": "Unauthorized", "status": 401, "code": "unauthorized"}
                else:
                    answers = owner.routes.get((method, self.path))
                    if answers is None:
                        status, body = 404, {"title": "Not found", "status": 404, "code": "not_found"}
                    else:
                        status, body = answers[0] if len(answers) == 1 else answers.pop(0)
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = lambda self: self.respond("GET")        # noqa: E731
            do_POST = lambda self: self.respond("POST")      # noqa: E731
            do_DELETE = lambda self: self.respond("DELETE")  # noqa: E731

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self) -> None:
        self.server.shutdown()


def check_smoke_patience() -> None:
    smoke = load_smoke()
    key = "k" * 43
    ready = (200, {"status": "ready", "checks": {"job_store": "ok", "analyzers": "ok"}})
    not_ready = (503, {"status": "not_ready", "checks": {"job_store": "ok", "analyzers": "failing"}})
    capabilities = (200, {"contract_version": "1.3.0", "languages": [{"id": "python", "roles": ["analyzer"]}], "features": {"fixes": False, "verifications": True}})
    running = {"id": "scn_1", "status": "running", "report": None}
    done = {"id": "scn_1", "status": "completed", "report": {"decision": "block", "findings": [
        {"id": "f1", "vulnerability_type": "command_injection", "severity": "high", "fix": {"eligible": True, "reason": "Medium severity or above."}}]}}

    def attempt(routes: dict, **options):
        pretend = PretendPhylax(key, routes)
        clock = [0.0]
        lines: list[str] = []
        try:
            passed = smoke.run(pretend.url, key, False, lines.append, sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds), clock=lambda: clock[0], **options)
        finally:
            pretend.stop()
        return passed, "\n".join(lines), clock[0], pretend.calls

    base = {("GET", "/healthz"): [(200, {"status": "ok"})], ("GET", "/readyz"): [ready], ("GET", "/v1/capabilities"): [capabilities], ("DELETE", "/v1/scans/scn_1"): [(204, None)]}

    # a cold start: not ready twice, and a scan that is still running when first asked about: the script WAITS, then passes
    passed, text, waited, calls = attempt({**base, ("GET", "/readyz"): [not_ready, not_ready, ready], ("POST", "/v1/scans"): [(202, running)], ("GET", "/v1/scans/scn_1"): [(200, running), (200, running), (200, done)]})
    assert passed and "FAIL" not in text, text
    assert "PASS  the service is ready" in text and "PASS  a vulnerable Python snippet is BLOCKED" in text
    assert waited >= 4.0, "it really waited (two readiness waits of 2 s each)"
    assert [c for c in calls if c[1] == "/readyz"].__len__() == 3 and [c for c in calls if c[0] == "GET" and c[1].startswith("/v1/scans/")].__len__() == 3
    assert ("DELETE", "/v1/scans/scn_1") in calls, "it cleans up the scan it made"

    # never ready: it gives up after the time allowed, says which of the service's own checks is failing, and still runs the other checks
    passed, text, waited, _ = attempt({**base, ("GET", "/readyz"): [not_ready], ("POST", "/v1/scans"): [(200, done)]}, ready_seconds=6)
    assert not passed and "FAIL  the service is ready (/readyz): status 503, job_store: ok, analyzers: failing" in text and "look at its logs" in text, text
    assert 6.0 <= waited < 20.0 and "PASS  a vulnerable Python snippet is BLOCKED" in text, "the rest of the checks still ran"

    # a scan that never finishes is reported as such, not as an unexplained empty result
    passed, text, _, _ = attempt({**base, ("POST", "/v1/scans"): [(202, running)], ("GET", "/v1/scans/scn_1"): [(200, running)]}, job_seconds=5)
    assert not passed and "still running after 5 s" in text and "decision None" in text, text

    # a refusal is described by the service's own code and request id, and nothing else from its answer is echoed
    busy = (503, {"title": "Busy", "status": 503, "code": "busy", "request_id": "req_abc", "detail": "SECRET-LOOKING DETAIL"})
    passed, text, _, _ = attempt({**base, ("POST", "/v1/scans"): [busy]})
    assert not passed and "status 503, code 'busy', request req_abc" in text and "SECRET-LOOKING DETAIL" not in text, text

    # when an engine could not run, the failure shows the engine's own reason (which contains no code)
    broken = {"id": "scn_1", "status": "completed", "report": {"decision": "scan_failed", "findings": [], "coverage": {"analyzers_failed": {"bandit": "bandit timed out after 30s (it printed nothing before it was stopped)"}}}}
    passed, text, _, _ = attempt({**base, ("POST", "/v1/scans"): [(200, broken)]})
    assert not passed and "decision 'scan_failed', 0 finding(s) [bandit: bandit timed out after 30s (it printed nothing before it was stopped)]" in text, text

    # describe() never echoes an unexpected body
    assert smoke.describe(500, {"oops": "hunter2"}) == "status 500" and smoke.describe(0, None) == "the service did not answer" and smoke.describe(200, "text") == "status 200"


def run() -> str:
    check_dockerfile()
    check_requirements()
    check_workflows()
    check_production_settings()
    check_smoke()
    check_smoke_patience()
    return ("check_deploy OK: Dockerfile (pinned, non-root, health check, nothing secret), pinned runtime packages with no test tool, workflows (pinned actions, smallest permissions, "
            "image smoke-tested before it is published), production settings read by the real config, smoke test passes and fails exactly when it should")


if __name__ == "__main__":
    try:
        print(run())
    except AssertionError as problem:
        print("DEPLOY CHECK FAILED:", problem)
        sys.exit(1)
