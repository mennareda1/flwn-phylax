"""
tests/check_service.py

The service as a person runs it: `python -m security_service.api` in its own process, settings from a .env file, real sockets,
and Decision-1 switched on against the fake Decision-1 server of check_transport.py. check_api.py proves the rules in-process;
this proves what only a real process can: that it starts, reads its settings, listens on its port, answers over HTTP, limits
an upload that has no Content-Length, logs without leaking, and refuses to start when it should.

    python -m tests.check_service
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from security_service.config import REPO_ROOT
from tests.check_transport import GOOD_KEY, FakeDecision1

KEY_FLWN = "Kq3vZ8nR2mXw5tYb7LcD9fGh1JpS4aUe"
KEY_VIEWER = "Zx9wQ2eR5tY7uI1oP3aS6dF8gH0jK4lM"
CANARY = "CANARY_55aa21"
CODE = f'import os\n# {CANARY}\ndef ping(host):\n    os.system("ping " + host)\n'


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def request(base, method, path, key=None, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **({"Authorization": f"Bearer {key}"} if key else {}), **(headers or {})}
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None), {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as problem:
        raw = problem.read()
        return problem.code, (json.loads(raw) if raw else None), {k.lower(): v for k, v in problem.headers.items()}


def start(env_path: Path, clean: dict, cwd: str, port_env: dict | None = None):
    env = {**clean, "SECURITY_ENV_FILE": str(env_path), "PYTHONPATH": str(REPO_ROOT), "PYTHONUNBUFFERED": "1", **(port_env or {})}
    return subprocess.Popen([sys.executable, "-m", "security_service.api"], cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8")


def run() -> None:
    try:
        model = FakeDecision1()
    except OSError as problem:
        print(f"check_service SKIPPED: this machine does not allow local sockets ({problem})")
        return
    threading.Thread(target=model.serve_forever, daemon=True).start()
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("FOUNDRY_", "DECISION1_", "SERVICE_", "CLASSIFIER_", "SCAN_"))}

    with tempfile.TemporaryDirectory() as folder:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env_path = Path(folder) / "service.env"
        # written the way Windows tools write it: a BOM and CRLF line endings
        env_path.write_bytes(("\ufeff" + "\r\n".join([
            f"FOUNDRY_ENDPOINT=http://127.0.0.1:{model.server_address[1]}",
            f"FOUNDRY_API_KEY={GOOD_KEY}",
            "DECISION1_DEPLOYMENT=decision-1",
            "CLASSIFIER_ENABLED=true",
            f"SERVICE_PORT={port}",
            f"SERVICE_API_KEYS=flwn-ai:scan+fix+read:{KEY_FLWN},viewer:read:{KEY_VIEWER}",
            "SERVICE_RATE_LIMIT_PER_MINUTE=500",
            "SERVICE_MAX_WAIT_SECONDS=20",
        ]) + "\r\n").encode("utf-8"))

        # ---- it REFUSES to start without a key, and when Decision-1 is switched on but not configured: said plainly, exit code 4, no trace
        for label, text in (("no key", f"SERVICE_PORT={port}\n"), ("Decision-1 on, not configured", f"SERVICE_PORT={port}\nCLASSIFIER_ENABLED=true\nSERVICE_API_KEYS=a:scan:{KEY_FLWN}\n")):
            bad = Path(folder) / "bad.env"
            bad.write_text(text, encoding="utf-8")
            refused = subprocess.run([sys.executable, "-m", "security_service.api"], cwd=folder, capture_output=True, text=True, encoding="utf-8", timeout=60,
                                     env={**clean, "SECURITY_ENV_FILE": str(bad), "PYTHONPATH": str(REPO_ROOT)})
            assert refused.returncode == 4 and "cannot start" in refused.stdout and "Traceback" not in refused.stdout + refused.stderr, (label, refused.stdout, refused.stderr)

        # ---- start it for real
        proc = start(env_path, clean, folder)
        output = ""
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    if request(base, "GET", "/healthz")[0] == 200:
                        break
                except (urllib.error.URLError, ConnectionError, OSError):
                    pass
                assert proc.poll() is None, "the service exited while starting:\n" + (proc.stdout.read() if proc.stdout else "")
                assert time.monotonic() < deadline, "the service did not start in 30 seconds"
                time.sleep(0.2)

            # ---- probes and capabilities over HTTP
            assert request(base, "GET", "/readyz")[1] == {"status": "ready", "checks": {"job_store": "ok", "analyzers": "ok"}}
            assert request(base, "GET", "/v1/capabilities")[0] == 401
            status, caps, headers = request(base, "GET", "/v1/capabilities", KEY_VIEWER)
            assert status == 200 and {"id": "python", "roles": ["analyzer", "classifier"]} in caps["languages"] and caps["limits"]["max_wait_seconds"] == 20
            assert headers["cache-control"] == "no-store" and headers["x-request-id"].startswith("req_")

            # ---- a scan end to end: client -> service -> rules AND the model -> report
            before = len(model.requests)
            status, scan, headers = request(base, "POST", "/v1/scans", KEY_FLWN, {"client_ref": "wi-9", "files": [{"path": "bad.py", "content": CODE}]},
                                            {"Prefer": "wait=20", "Idempotency-Key": "e2e-1"})
            assert status == 200 and scan["status"] == "completed" and scan["client_ref"] == "wi-9", (status, scan)
            report = scan["report"]
            assert report["decision"] == "block"                                           # a rule-backed high finding blocks...
            tiers = {f["evidence_tier"] for f in report["findings"]}
            assert "model_suspicion" in tiers and ("corroborated" in tiers or "static_rule" in tiers)    # ...and the model's findings are there too, as suspicion
            assert any(r["name"] == "microsoft-decision-1" and r["role"] == "classifier" for r in report["provenance"]["engines"])
            sent = model.requests[before:]
            assert len(sent) == 1 and len(sent[0]["body"]["questions"]) == 12              # exactly one model request, with the 12 questions
            assert KEY_FLWN not in json.dumps(sent) and KEY_VIEWER not in json.dumps(sent)  # the service's own keys never go to the model

            # ---- a retry is the same scan; a read-only key cannot create; nobody else can read it
            status, again, headers = request(base, "POST", "/v1/scans", KEY_FLWN, {"client_ref": "wi-9", "files": [{"path": "bad.py", "content": CODE}]},
                                             {"Prefer": "wait=20", "Idempotency-Key": "e2e-1"})
            assert again["id"] == scan["id"] and headers["idempotency-replayed"] == "true" and len(model.requests) == before + 1   # no second model call
            assert request(base, "POST", "/v1/scans", KEY_VIEWER, {"files": [{"path": "a.py", "content": "x = 1"}]})[0] == 403
            assert request(base, "GET", f"/v1/scans/{scan['id']}", KEY_VIEWER)[0] == 404
            assert request(base, "GET", f"/v1/scans/{scan['id']}", KEY_FLWN)[0] == 200

            # ---- an upload over the limit is refused WITHOUT being held in memory: with a Content-Length, and without one (chunked)
            huge = {"files": [{"path": "a.py", "content": "x" * 3_000_000}]}
            status, problem, _ = request(base, "POST", "/v1/scans", KEY_FLWN, huge)
            assert status == 413 and problem["code"] == "payload_too_large"
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            connection.request("POST", "/v1/scans", body=(b"x" * 100_000 for _ in range(30)), encode_chunked=True,
                               headers={"Authorization": f"Bearer {KEY_FLWN}", "Content-Type": "application/json"})
            chunked = connection.getresponse()
            assert chunked.status == 413 and json.loads(chunked.read())["code"] == "payload_too_large"
            connection.close()
            try:                                                                              # without a key the body is never read: a 401, or the connection simply closes
                assert request(base, "POST", "/v1/scans", None, huge)[0] == 401
            except (urllib.error.URLError, ConnectionError, OSError):
                pass

            # ---- the honest answers for what is not built, a Problem for everything unknown, and delete
            assert request(base, "POST", f"/v1/scans/{scan['id']}/fixes", KEY_FLWN, {})[1]["code"] == "not_implemented"
            assert request(base, "GET", "/v1/nothing", KEY_FLWN)[1]["code"] == "not_found"
            assert request(base, "DELETE", f"/v1/scans/{scan['id']}", KEY_FLWN)[0] == 204
            assert request(base, "GET", f"/v1/scans/{scan['id']}", KEY_FLWN)[0] == 404
        finally:
            proc.terminate()
            try:
                output = proc.communicate(timeout=20)[0]
            except subprocess.TimeoutExpired:
                proc.kill()
                output = proc.communicate()[0]

        # ---- what the service printed: it says who and what, and never a key or a line of the submitted code
        assert "http://127.0.0.1" in output and "flwn-ai (scan+fix+read)" in output and "Starting" in output
        assert "POST /v1/scans -> 200" in output and "caller=flwn-ai" in output and "req_" in output, output[-1500:]
        for secret in (KEY_FLWN, KEY_VIEWER, GOOD_KEY, CANARY, "os.system", "ping"):
            assert secret not in output, f"{secret[:12]!r} appeared in the service's output"

    print("check_service OK: the real process starts from a .env (BOM + CRLF), serves over real sockets, scans with the rules and Decision-1, replays a retry without a second model call, "
          "limits an upload with or without Content-Length, refuses to start without a key or with a broken Decision-1 setup, and its output never holds a key or the submitted code")


if __name__ == "__main__":
    run()
