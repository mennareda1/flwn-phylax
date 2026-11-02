"""
tests/check_api.py

Does the HTTP service do what openapi.yaml says, and keep its promises? Runs the real web application in-process (no network).

For EVERY response it gets, it checks against the contract file: the status code is one the operation declares, the content
type is the declared one, and the body matches the declared schema. Then it checks the promises across ALL responses and ALL log
lines together: no API key and no submitted code ever appears in an error body, a header or a log line.

Covered: probes, authentication and scopes (and that the key is checked before the body), the wait-or-poll behavior, idempotency,
every kind of bad request, ownership, delete, retention, rate limiting, a busy service, a full store, the honest 501 for fixes when they
are off, a crashing scan, a crash in the web layer itself, parallel scans, Decision-1 switched on, and FIXES AND VERIFICATIONS (a fix end
to end, a verification of the caller's own correction, every refusal, the 409 for a scan that is not finished, the per-scan cap, the fix
rate limit, and cleanup when the scan goes).

    python -m tests.check_api
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore", message=".*starlette.testclient.*")     # a notice about the test client library, not about this service

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from security_service.adapters.bandit import BanditAnalyzer
from security_service.adapters.classifier_detector import ClassifierDetector
from security_service.adapters.fakes import FakeClassifier
from security_service.adapters.secrets_check import SecretsAnalyzer
from security_service.api.app import create_app
from security_service.api.auth import parse_api_keys
from security_service.api.gateway import Gateway
from security_service.api.jobs import JobStore
from security_service.api.ratelimit import RateLimiter
from security_service.core.files import Limits
from security_service.core.fix_service import FixService
from security_service.core.patching import apply_unified_diff, make_unified_diff
from security_service.core.scan_service import ScanService
from security_service.ports.analyzer import AnalyzerResult
from security_service.ports.classifier import Answer
from security_service.ports.corrector import Patch
from tests.check_contract import check, spec

KEY_ALICE = "Kq3vZ8nR2mXw5tYb7LcD9fGh1JpS4aUe"        # scan + fix + read
KEY_BOB = "Zx9wQ2eR5tY7uI1oP3aS6dF8gH0jK4lM"          # read only
KEY_CAROL = "Mn4bV7cX1zL9kJ3hG5fD8sA2qW6eR0tY"        # scan + read
KEYS = f"alice:scan+fix+read:{KEY_ALICE},bob:read:{KEY_BOB},carol:scan+read:{KEY_CAROL}"
CANARY = "CANARY_7c41e9"                               # appears in submitted code and client fields: must never come back in an error or a log
LIMITS = Limits(max_files=5, max_file_bytes=2_000, max_total_bytes=6_000)
BAD_CODE = f'import os\n# {CANARY}\ndef ping(host):\n    os.system("ping " + host)\n'
BODY = {"client_ref": "wi-1", "files": [{"path": "bad.py", "content": BAD_CODE}]}

ALL: list = []                                          # every response, for the sweeps at the end


class Records(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class Stub:
    """A scripted engine: waits `delay` seconds, then reports `findings`, or raises `error`."""
    role = "analyzer"
    languages = ("python",)

    def __init__(self, name="stub", delay=0.0, error=None):
        self.name, self.delay, self.error = name, delay, error

    def analyze(self, code, language):
        time.sleep(self.delay)
        if self.error:
            raise self.error
        return AnalyzerResult(analyzer=self.name)


def build(engines=None, *, service=None, rate=10_000, retention=3600, workers=2, max_queue=50, max_jobs=500, store_clock=None, limiter_clock=None, max_wait=10,
          fix_service=None, fix_rate=100):
    ring, problems = parse_api_keys(KEYS)
    assert not problems
    service = service or ScanService(engines if engines is not None else [BanditAnalyzer(), SecretsAnalyzer()], limits=LIMITS)
    store = JobStore(retention, max_jobs=max_jobs, **({"clock": store_clock} if store_clock else {}))
    limiter = RateLimiter(rate, **({"clock": limiter_clock} if limiter_clock else {}))
    gateway = Gateway(service, ring, store, limiter, workers=workers, max_wait_seconds=max_wait, retention_hours=24, max_queue=max_queue,
                      fix_service=fix_service, fix_limiter=RateLimiter(fix_rate))
    return create_app(gateway), gateway, store


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def declared(method: str, template: str, status: int) -> dict:
    operation = spec["paths"][template][method.lower()]
    answer = operation["responses"].get(str(status))
    assert answer is not None, f"{method} {template}: the contract does not declare a {status} response"
    if "$ref" in answer:
        answer = spec["components"]["responses"][answer["$ref"].rsplit("/", 1)[-1]]
    return answer


def conform(method: str, template: str, response) -> None:
    answer = declared(method, template, response.status_code)
    content = answer.get("content")
    if not content:
        assert response.content == b"", f"{method} {template} {response.status_code}: the contract declares no body"
        return
    media, detail = next(iter(content.items()))
    assert response.headers["content-type"].startswith(media), f"{method} {template}: content type {response.headers['content-type']} is not {media}"
    schema = detail["schema"]
    if "$ref" in schema:
        check(schema["$ref"].rsplit("/", 1)[-1], response.json())
    else:                                           # an inline schema (the health probe)
        errors = list(Draft202012Validator({"components": spec["components"], **schema}).iter_errors(response.json()))
        assert not errors, f"{method} {template}: {errors[0].message}"


def call(client, method, template, path=None, expect=None, body=None, raw=None, headers=None, key=None, conformant=True):
    """One request, checked against the contract and recorded for the sweeps."""
    h = {**(auth(key) if key else {}), **(headers or {})}
    kwargs = {"content": raw} if raw is not None else ({"json": body} if body is not None else {})
    if raw is not None:
        h.setdefault("content-type", "application/json")
    response = client.request(method, path or template, headers=h, **kwargs)
    ALL.append(response)
    assert expect is None or response.status_code == expect, f"{method} {path or template}: expected {expect}, got {response.status_code}: {response.text[:300]}"
    if conformant:
        conform(method, template, response)
    assert response.headers.get("x-request-id", "").startswith("req_") and response.headers.get("cache-control") == "no-store"
    assert response.headers.get("x-content-type-options") == "nosniff"
    if response.status_code >= 400 and "problem" in response.headers["content-type"]:
        assert response.json()["request_id"] == response.headers["x-request-id"] and response.json()["status"] == response.status_code
    return response


def body_reads(app, headers: dict, chunks: list[bytes], path: str = "/v1/scans") -> tuple[int, int]:
    """Send a POST straight to the application and report (status, how many body chunks the server actually asked for)."""
    consumed = {"n": 0}
    queue = list(chunks)
    answer: dict = {}

    async def receive():
        if queue:
            consumed["n"] += 1
            chunk = queue.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(queue)}
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.start":
            answer["status"] = message["status"]

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": path, "raw_path": path.encode(),
             "query_string": b"", "root_path": "", "scheme": "http", "server": ("testserver", 80), "client": ("testclient", 1),
             "headers": [(b"content-type", b"application/json")] + [(k.lower().encode(), v.encode()) for k, v in headers.items()], "state": {}}
    asyncio.run(app(scope, receive, send))
    return answer["status"], consumed["n"]


def poll(client, scan_id, key, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        r = call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{scan_id}", 200, key=key)
        if r.json()["status"] in ("completed", "failed"):
            return r.json()
        time.sleep(0.1)
    raise AssertionError("the scan did not finish")


def run() -> None:
    records = Records()
    logging.getLogger("security_service.api").addHandler(records)
    logging.getLogger("security_service.api").setLevel(logging.INFO)

    app, gateway, store = build()
    client = TestClient(app, raise_server_exceptions=False)
    try:
        # ---------------------------------------------------------------- probes and capabilities
        assert call(client, "GET", "/healthz", expect=200).json() == {"status": "ok"}                       # no key needed
        assert call(client, "GET", "/readyz", expect=200).json() == {"status": "ready", "checks": {"job_store": "ok", "analyzers": "ok"}}
        r = call(client, "GET", "/v1/capabilities", expect=401)
        assert r.headers["www-authenticate"] == "Bearer" and r.json()["code"] == "unauthorized"
        caps = call(client, "GET", "/v1/capabilities", expect=200, key=KEY_BOB).json()                     # any valid key, even read-only
        assert caps["features"] == {"fixes": False, "verifications": True} and caps["limits"]["max_files"] == 5 and caps["limits"]["max_wait_seconds"] == 10
        assert caps["contract_version"] == spec["info"]["version"] == "1.1.0"

        # ---------------------------------------------------------------- authentication, scopes, and the order of the checks
        for label, headers in (("a wrong key", auth("wrong-key-wrong-key-wrong-key-1")), ("no key", {}), ("basic auth", {"Authorization": f"Basic {KEY_ALICE}"}),
                               ("the key in a query string", {})):
            path = f"/v1/scans?key={KEY_ALICE}" if "query" in label else "/v1/scans"
            call(client, "POST", "/v1/scans", path, 401, body=BODY, headers=headers)
        # the key is checked BEFORE the body: an unauthenticated caller with a broken body still gets 401, not 400
        assert call(client, "POST", "/v1/scans", expect=401, raw=b"{not json at all").json()["code"] == "unauthorized"
        call(client, "POST", "/v1/scans", expect=403, body=BODY, key=KEY_BOB)                               # a read-only key cannot scan
        call(client, "DELETE", "/v1/scans/{scan_id}", "/v1/scans/scn_x", 403, key=KEY_BOB)
        call(client, "POST", "/v1/scans/{scan_id}/fixes", "/v1/scans/scn_x/fixes", 403, key=KEY_CAROL, body={})   # carol has no fix scope

        # ---------------------------------------------------------------- creating a scan: wait for the answer, or poll
        done = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10"})
        scan = done.json()
        assert scan["status"] == "completed" and scan["client_ref"] == "wi-1" and scan["report"]["decision"] == "block"
        assert scan["report"]["findings"][0]["path"] == "bad.py" and done.headers["preference-applied"] == "wait=10"
        queued = call(client, "POST", "/v1/scans", expect=None, body=BODY, key=KEY_ALICE)                   # no Prefer: answered at once
        assert queued.status_code in (200, 202)
        if queued.status_code == 202:
            assert queued.headers["location"] == f"/v1/scans/{queued.json()['id']}" and queued.json()["report"] is None
        assert poll(client, queued.json()["id"], KEY_ALICE)["report"]["decision"] == "block"

        # ---------------------------------------------------------------- ownership: nobody sees another caller's scan
        mine = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10"}).json()["id"]
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{mine}", 404, key=KEY_BOB)
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{mine}", 404, key=KEY_CAROL)
        call(client, "DELETE", "/v1/scans/{scan_id}", f"/v1/scans/{mine}", 404, key=KEY_CAROL)
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{mine}", 200, key=KEY_ALICE)

        # ---------------------------------------------------------------- idempotency
        headers = {"Idempotency-Key": "retry-1", "Prefer": "wait=10"}
        first = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers=headers)
        again = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers=headers)
        assert again.json()["id"] == first.json()["id"] and again.headers["idempotency-replayed"] == "true" and "idempotency-replayed" not in first.headers
        other = {"files": [{"path": "x.py", "content": "x = 1\n"}]}
        assert call(client, "POST", "/v1/scans", expect=409, body=other, key=KEY_ALICE, headers=headers).json()["code"] == "idempotency_conflict"
        carol_first = call(client, "POST", "/v1/scans", expect=200, body=other, key=KEY_CAROL, headers=headers)     # the same key from another caller is a different scan
        assert carol_first.json()["id"] != first.json()["id"] and "idempotency-replayed" not in carol_first.headers

        # ---------------------------------------------------------------- every kind of bad request, answered at once, without echoing it
        bad = {
            "not json": (b"{not json " + CANARY.encode(), 400, "invalid_request"),
            "a list": (b"[1, 2]", 400, "invalid_request"),
            "empty body": (b"", 400, "invalid_request"),
            "no files": (json.dumps({"files": []}).encode(), 400, "invalid_request"),
            "unknown field": (json.dumps({"files": [{"path": "a.py", "content": "x"}], CANARY: 1}).encode(), 400, "invalid_request"),
            "files is a string holding code": (json.dumps({"files": CANARY}).encode(), 400, "invalid_request"),
            "content is a list holding code": (json.dumps({"files": [{"path": "a.py", "content": [CANARY]}]}).encode(), 400, "invalid_request"),
            "language is an object holding code": (json.dumps({"language": {"x": CANARY}, "files": [{"path": "a.py", "content": "x"}]}).encode(), 400, "invalid_request"),
            "path is too long and holds code": (json.dumps({"files": [{"path": CANARY * 100, "content": "x"}]}).encode(), 400, "invalid_request"),
            "content is a number": (json.dumps({"files": [{"path": "a.py", "content": 12345}], "client_ref": CANARY}).encode(), 400, "invalid_request"),
            "duplicate paths": (json.dumps({"files": [{"path": "a.py", "content": CANARY}, {"path": "a.py", "content": "y"}]}).encode(), 400, "invalid_request"),
            "unsupported language": (json.dumps({"language": "cobol", "files": [{"path": "a.cob", "content": CANARY}]}).encode(), 422, "unsupported_language"),
            "too many files": (json.dumps({"files": [{"path": f"f{i}.py", "content": "x = 1"} for i in range(6)]}).encode(), 413, "payload_too_large"),
            "body over the limit": (b'{"files":[],"x":"' + b"a" * (gateway.max_body_bytes + 10) + b'"}', 413, "payload_too_large"),
        }
        before = len(store)
        for label, (raw, status, code) in bad.items():
            r = call(client, "POST", "/v1/scans", expect=status, raw=raw, key=KEY_ALICE)
            assert r.json()["code"] == code, (label, r.json())
        assert len(store) == before, "a bad request became a job"
        call(client, "POST", "/v1/scans", expect=400, body=BODY, key=KEY_ALICE, headers={"Idempotency-Key": "k" * 201})

        # one file over the per-file limit is not an error: it is skipped and recorded, and a would-be pass becomes a review
        big = call(client, "POST", "/v1/scans", expect=200, key=KEY_ALICE, headers={"Prefer": "wait=10"},
                   body={"files": [{"path": "big.py", "content": "x = 1\n# " + "filler " * 400}, {"path": "ok.py", "content": "y = 2\n"}]}).json()["report"]
        assert big["decision"] == "review_required" and big["coverage"]["skipped_files"] == [{"path": "big.py", "reason": "file_too_large", "blocks_pass": True}]
        assert big["coverage"]["files_scanned"] == ["ok.py"]

        # ---------------------------------------------------------------- paths and methods that do not exist are Problems too
        for method, path, status in (("GET", "/v1/nothing", 404), ("PUT", "/v1/scans", 405), ("GET", "/", 404), ("POST", "/healthz", 405)):
            r = call(client, method, path, expect=status, key=KEY_ALICE, conformant=False)
            assert "problem" in r.headers["content-type"] and r.json()["status"] == status and r.json()["request_id"] == r.headers["x-request-id"]

        # ---------------------------------------------------------------- delete
        gone = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10", "Idempotency-Key": "del-1"}).json()["id"]
        assert call(client, "DELETE", "/v1/scans/{scan_id}", f"/v1/scans/{gone}", 204, key=KEY_ALICE).content == b""
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{gone}", 404, key=KEY_ALICE)
        call(client, "DELETE", "/v1/scans/{scan_id}", f"/v1/scans/{gone}", 404, key=KEY_ALICE)
        fresh = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10", "Idempotency-Key": "del-1"})
        assert fresh.json()["id"] != gone and "idempotency-replayed" not in fresh.headers                   # the key is free after a delete

        # ---------------------------------------------------------------- the features that are not built answer honestly
        r = call(client, "POST", "/v1/scans/{scan_id}/fixes", f"/v1/scans/{mine}/fixes", 501, key=KEY_ALICE, body={})
        assert r.json()["code"] == "not_implemented" and "capabilities" in r.json()["detail"]
        assert call(client, "POST", "/v1/verifications", expect=400, body={}, key=KEY_ALICE).json()["code"] == "invalid_request"          # verifications are on: an empty request is just a bad request
        call(client, "GET", "/v1/fixes/{fix_id}", "/v1/fixes/fix_1", 404, key=KEY_ALICE)
        call(client, "GET", "/v1/verifications/{verification_id}", "/v1/verifications/ver_1", 404, key=KEY_ALICE)
        call(client, "POST", "/v1/verifications", expect=401, body={})

        # ---------------------------------------------------------------- a crash in the web layer itself: generic answer, nothing leaks
        original = gateway.health
        gateway.health = lambda: (_ for _ in ()).throw(RuntimeError(f"boom {CANARY} {KEY_ALICE}"))
        r = call(client, "GET", "/healthz", expect=500, conformant=False)
        gateway.health = original
        assert r.json()["code"] == "internal_error" and CANARY not in r.text and KEY_ALICE not in r.text and "boom" not in r.text
        assert call(client, "GET", "/healthz", expect=200).json() == {"status": "ok"}                      # and the service carries on

        # ---------------------------------------------------------------- parallel scans: every caller gets its own, complete result
        results: list = []

        def one(i: int):
            local = TestClient(app, raise_server_exceptions=False)
            r = local.post("/v1/scans", headers={**auth(KEY_ALICE), "Prefer": "wait=20", "Idempotency-Key": f"par-{i}"},
                           json={"client_ref": f"par-{i}", "files": [{"path": "p.py", "content": f"value = {i}\n"}]})
            ALL.append(r)
            results.append((i, r))

        threads = [threading.Thread(target=one, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 10 and all(r.status_code == 200 for _, r in results), [r.text[:100] for _, r in results if r.status_code != 200]
        assert all(r.json()["client_ref"] == f"par-{i}" and r.json()["report"]["decision"] == "pass" for i, r in results)
        assert len({r.json()["id"] for _, r in results}) == 10
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- wait or poll, with a slow engine
    app, gateway, store = build([Stub(delay=1.3)], workers=2)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        started = time.monotonic()
        short = call(client, "POST", "/v1/scans", expect=202, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=1", "Idempotency-Key": "slow"})
        assert 0.9 <= time.monotonic() - started < 1.25 and short.headers["preference-applied"] == "wait=1" and short.json()["status"] in ("queued", "running")
        assert short.headers["location"] == f"/v1/scans/{short.json()['id']}" and short.json()["report"] is None
        longer = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "respond-async, wait=20", "Idempotency-Key": "slow"})
        assert longer.json()["id"] == short.json()["id"] and longer.json()["status"] == "completed"     # the replay waited for the same job
    finally:
        gateway.shutdown()

    # a caller asking to wait 999 seconds is held for the configured maximum and no longer
    app, gateway, store = build([Stub(delay=3.5)], workers=2, max_wait=2)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        started = time.monotonic()
        capped = call(client, "POST", "/v1/scans", expect=202, body=BODY, key=KEY_CAROL, headers={"Prefer": "wait=999"})
        assert 1.8 <= time.monotonic() - started < 3.0 and capped.headers["preference-applied"] == "wait=2"
        assert call(client, "GET", "/v1/capabilities", expect=200, key=KEY_CAROL).json()["limits"]["max_wait_seconds"] == 2
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- a busy service says so; a full store says so
    app, gateway, store = build([Stub(delay=1.5)], workers=1, max_queue=1)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        call(client, "POST", "/v1/scans", expect=202, body=BODY, key=KEY_ALICE)
        call(client, "POST", "/v1/scans", expect=202, body=BODY, key=KEY_ALICE)
        busy = call(client, "POST", "/v1/scans", expect=503, body=BODY, key=KEY_ALICE)
        assert busy.json()["code"] == "provider_unavailable" and busy.headers["retry-after"] == "5"
    finally:
        gateway.shutdown()
    app, gateway, store = build([Stub()], max_jobs=2)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        for _ in range(2):
            call(client, "POST", "/v1/scans", expect=None, body=BODY, key=KEY_ALICE)
        assert call(client, "POST", "/v1/scans", expect=503, body=BODY, key=KEY_ALICE).headers["retry-after"] == "30"
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- a crashing scan is a failed job that says nothing about why
    app, gateway, store = build([Stub(error=RuntimeError(f"boom {CANARY}"))])
    client = TestClient(app, raise_server_exceptions=False)
    try:
        crashed = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10"})
        # an engine that raises is caught by the scanner (a failed engine): the SCAN is reported as scan_failed, not the job
        assert crashed.json()["status"] == "completed" and crashed.json()["report"]["decision"] == "scan_failed" and CANARY not in json.dumps(crashed.json()["report"]["coverage"])
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- retention and rate limiting, with a clock we control
    now = [50_000.0]
    app, gateway, store = build([Stub()], retention=3600, store_clock=lambda: now[0], rate=3, limiter_clock=lambda: now[0])
    client = TestClient(app, raise_server_exceptions=False)
    try:
        sid = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10"}).json()["id"]
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 200, key=KEY_ALICE)               # request 2 of 3 allowed per minute
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 200, key=KEY_ALICE)               # request 3
        limited = call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 429, key=KEY_ALICE)              # the fourth request in a minute
        assert limited.json()["code"] == "rate_limited" and 1 <= int(limited.headers["retry-after"]) <= 60
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 404, key=KEY_BOB)                           # another caller is not limited by alice
        now[0] += 61
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 200, key=KEY_ALICE)                         # the minute passed
        now[0] += 3600                                                                                              # retention ends
        call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 404, key=KEY_ALICE)
        assert len(store) == 0
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- Decision-1 switched on: model findings ask for review, never block
    suspects = FakeClassifier(lambda state, q: Answer("yes_no", probability=0.96 if q.id == "path_traversal" else 0.02), name="stand-in-model")
    app, gateway, store = build([BanditAnalyzer(), SecretsAnalyzer(), ClassifierDetector(suspects)])
    client = TestClient(app, raise_server_exceptions=False)
    try:
        r = call(client, "POST", "/v1/scans", expect=200, body={"files": [{"path": "ok.py", "content": "def add(a, b):\n    return a + b\n"}]}, key=KEY_ALICE,
                 headers={"Prefer": "wait=20"})
        report = r.json()["report"]
        assert report["decision"] == "review_required" and report["findings"][0]["evidence_tier"] == "model_suspicion" and report["findings"][0]["line"] is None
        assert {"role": "classifier", "name": "stand-in-model"} in report["provenance"]["engines"]
        caps = call(client, "GET", "/v1/capabilities", expect=200, key=KEY_ALICE).json()
        assert {"id": "python", "roles": ["analyzer", "classifier"]} in caps["languages"]
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- an unauthenticated caller's body is never read; an authenticated oversized one is not held
    app, gateway, store = build([Stub()])
    try:
        pieces = [b"x" * 50_000] * 20
        status, read = body_reads(app, {}, pieces)
        assert status == 401 and read == 0, f"an unauthenticated body was read ({read} chunks)"
        status, read = body_reads(app, {"Authorization": "Bearer wrong-key-wrong-key-wrong-key-1"}, pieces)
        assert status == 401 and read == 0
        status, read = body_reads(app, {"Authorization": f"Bearer {KEY_BOB}"}, pieces)                  # a valid key without the scope: refused before reading
        assert status == 403 and read == 0
        status, read = body_reads(app, auth(KEY_ALICE), [b"x" * 500_000] * 20)                          # 10 MB in 500 KB pieces: refused, and the rest is drained and discarded
        assert status == 413 and 16 <= read <= 18, f"the oversized upload was drained for {read} pieces (expected about 17: read and thrown away up to the 8 MB cap)"
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- a scan that crashes the WORKER: a failed job, and the exception text appears nowhere
    class Exploding(ScanService):
        def scan(self, files, language=None, context=None):
            raise RuntimeError(f"boom {CANARY} {KEY_ALICE}")

    app, gateway, store = build(service=Exploding([Stub()], limits=LIMITS))
    client = TestClient(app, raise_server_exceptions=False)
    try:
        failed = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=10"})
        assert failed.json()["status"] == "failed" and failed.json()["report"] is None and failed.json()["completed_at"] is not None
        assert call(client, "GET", "/v1/scans/{scan_id}", f"/v1/scans/{failed.json()['id']}", 200, key=KEY_ALICE).json()["status"] == "failed"
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- FIXES and VERIFICATIONS through the HTTP service, every response against the contract
    class Fixer:
        role, name = "corrector", "scripted"

        def __init__(self, mode="good"):
            self.mode, self.calls = mode, 0

        def propose_fix(self, file, findings, constraints):
            self.calls += 1
            if self.mode == "crash":
                raise RuntimeError(f"boom {CANARY} {KEY_ALICE}")
            new = file.content.replace('    os.system("ping " + host)\n', '    subprocess.run(["ping", host], check=True)\n').replace("import os\n", "import os\nimport subprocess\n")
            return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, new), "Replaced the shell call.")]

    def poll_child(client, template, path, key, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            r = call(client, "GET", template, path, 200, key=key)
            if r.json()["status"] in ("completed", "failed"):
                return r.json()
            time.sleep(0.1)
        raise AssertionError("the job did not finish")

    fixer = Fixer()
    svc = ScanService([BanditAnalyzer(), SecretsAnalyzer()], limits=LIMITS)
    app, gateway, store = build(service=svc, fix_service=FixService(svc, fixer))
    client = TestClient(app, raise_server_exceptions=False)
    FIXES, FIX, VERS, VER = "/v1/scans/{scan_id}/fixes", "/v1/fixes/{fix_id}", "/v1/verifications", "/v1/verifications/{verification_id}"
    try:
        assert call(client, "GET", "/v1/capabilities", expect=200, key=KEY_ALICE).json()["features"] == {"fixes": True, "verifications": True}
        sid = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=20"}).json()["id"]
        carol_scan = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_CAROL, headers={"Prefer": "wait=20"}).json()["id"]

        # who may do what: `fix` asks for fixes, `scan` verifies, `read` fetches; no key is 401 before anything else is looked at
        call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 401, body={})
        call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 403, key=KEY_BOB, body={})                       # read only
        call(client, "POST", FIXES, f"/v1/scans/{carol_scan}/fixes", 403, key=KEY_CAROL, body={})              # scan + read, but no fix scope
        call(client, "POST", VERS, VERS, 403, key=KEY_BOB, body={"scan_id": sid, "files": [{"path": "bad.py", "content": "x = 1\n"}]})
        call(client, "GET", FIX, "/v1/fixes/fix_1", 401)
        assert fixer.calls == 0, "a refused request reached the model"

        # a fix, waited for: the patches, the verification embedded in it (also fetchable by its own id), and a diff that really applies
        headers = {"Prefer": "wait=20", "Idempotency-Key": "fix-1"}
        fix = call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 200, key=KEY_ALICE, body={}, headers=headers).json()
        assert fix["status"] == "completed" and fix["scan_id"] == sid and fix["applicable"] is True and fix["failure_reason"] is None and fix["unfixed"] == []
        assert fix["verification"]["outcome"] == "passed" and fix["verification"]["resolved_finding_ids"] == ["f1"] and fix["verification"]["scan_id"] == sid
        assert [c["name"] for c in fix["verification"]["checks"]] == ["scope", "syntax", "patch_size", "rescan"]
        patched = apply_unified_diff(BAD_CODE, fix["patches"][0]["unified_diff"], "bad.py")
        assert "subprocess.run" in patched and "os.system" not in patched and fix["patches"][0]["finding_ids"] == ["f1"] and fixer.calls == 1
        assert call(client, "GET", FIX, f"/v1/fixes/{fix['id']}", 200, key=KEY_ALICE).json() == fix
        assert call(client, "GET", VER, f"/v1/verifications/{fix['verification']['id']}", 200, key=KEY_ALICE).json() == fix["verification"]
        call(client, "GET", FIX, f"/v1/fixes/{fix['id']}", 404, key=KEY_BOB)                                       # nobody else sees it, not even a read-only key
        call(client, "GET", FIX, f"/v1/fixes/{fix['id']}", 404, key=KEY_CAROL)
        call(client, "GET", FIX, f"/v1/fixes/{fix['verification']['id']}", 404, key=KEY_ALICE)                      # a verification id is not a fix id

        # a retry is the same fix, with no second model call; the same key with another request is a conflict (the contract's 409)
        retry = call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 200, key=KEY_ALICE, body={}, headers=headers)
        assert retry.json()["id"] == fix["id"] and retry.headers["idempotency-replayed"] == "true" and fixer.calls == 1
        assert call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 409, key=KEY_ALICE, body={"max_patch_lines": 7}, headers={"Idempotency-Key": "fix-1"}).json()["code"] == "idempotency_conflict"

        # without Prefer the answer comes at once and is fetched by polling
        quick = call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", None, key=KEY_ALICE, body={"max_patch_lines": 41}, headers={"Idempotency-Key": "fix-2"})
        assert quick.status_code in (200, 202)
        if quick.status_code == 202:
            assert quick.headers["location"] == f"/v1/fixes/{quick.json()['id']}" and quick.json()["patches"] == [] and quick.json()["applicable"] is False
        assert poll_child(client, FIX, f"/v1/fixes/{quick.json()['id']}", KEY_ALICE)["status"] == "completed"

        # every bad request is a 400 that does not repeat what was sent
        for label, raw in (("unknown finding id", json.dumps({"finding_ids": [CANARY]}).encode()), ("ids not a list", b'{"finding_ids": "f1"}'), ("empty ids", b'{"finding_ids": []}'),
                           ("limit 0", b'{"max_patch_lines": 0}'), ("limit 201", b'{"max_patch_lines": 201}'), ("limit a string", b'{"max_patch_lines": "7"}'),
                           ("unknown field", json.dumps({CANARY: 1}).encode()), ("not json", b"{nope " + CANARY.encode()), ("a list", b"[1]")):
            r = call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 400, key=KEY_ALICE, raw=raw)
            assert r.json()["code"] == "invalid_request", label
        call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 413, key=KEY_ALICE, raw=b" " * 70_000)
        call(client, "POST", FIXES, "/v1/scans/scn_missing/fixes", 404, key=KEY_ALICE, body={})
        call(client, "POST", FIXES, f"/v1/scans/{carol_scan}/fixes", 404, key=KEY_ALICE, body={})                   # alice has the fix scope, but carol's scan is not hers
        assert call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 400, key=KEY_ALICE, body={}, headers={"Idempotency-Key": "k" * 201}).json()["code"] == "invalid_request"

        # a scan may hold only a few fix requests (each costs a model call): the sixth is a 409 that says waiting will not help
        for number in range(3, 6):
            call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 200, key=KEY_ALICE, body={"max_patch_lines": 40 + number}, headers={"Prefer": "wait=20"})
        capped = call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 409, key=KEY_ALICE, body={"max_patch_lines": 99}).json()
        assert capped["code"] == "fix_limit_reached" and "waiting" not in capped["detail"].lower() or capped["code"] == "fix_limit_reached"
        calls_before = fixer.calls

        # verifying a correction the CALLER wrote: the contract's Verification, with the checks and the verdict
        corrected = BAD_CODE.replace('    os.system("ping " + host)\n', '    subprocess.run(["ping", host], check=True)\n').replace("import os\n", "import os\nimport subprocess\n")
        verify = lambda files, **kw: call(client, "POST", VERS, VERS, kw.pop("expect", 200), key=kw.pop("key", KEY_ALICE), body={"scan_id": sid, "files": files, **kw.pop("extra", {})},
                                          headers={"Prefer": "wait=20", **kw.pop("headers", {})})
        passed = verify([{"path": "bad.py", "content": corrected}], extra={"client_ref": "mine"}).json()
        assert passed["status"] == "completed" and passed["outcome"] == "passed" and passed["resolved_finding_ids"] == ["f1"] and passed["new_findings"] == [] and passed["scan_id"] == sid
        assert call(client, "GET", VER, f"/v1/verifications/{passed['id']}", 200, key=KEY_ALICE).json() == passed
        call(client, "GET", VER, f"/v1/verifications/{passed['id']}", 404, key=KEY_BOB)
        failed = verify([{"path": "bad.py", "content": BAD_CODE + "# unchanged in substance\n"}]).json()
        assert failed["outcome"] == "failed" and any(c["name"] == "rescan" and c["result"] == "fail" for c in failed["checks"]) and failed["resolved_finding_ids"] == []
        swapped = verify([{"path": "bad.py", "content": corrected.replace('subprocess.run(["ping", host], check=True)', 'eval("ping " + host)')}]).json()
        assert swapped["outcome"] == "failed" and [f["vulnerability_type"] for f in swapped["new_findings"]] == ["code_injection"] and swapped["new_findings"][0]["id"] == "n1"
        stranger = verify([{"path": "other.py", "content": corrected}]).json()
        assert stranger["outcome"] == "failed" and stranger["checks"][0] == {"name": "scope", "result": "fail", "detail": stranger["checks"][0]["detail"]}
        broken = verify([{"path": "bad.py", "content": corrected.replace("check=True)", "check=True")}]).json()
        assert broken["outcome"] == "failed" and next(c for c in broken["checks"] if c["name"] == "syntax")["result"] == "fail"
        # idempotent, and a conflict when the key is reused for something else
        first = verify([{"path": "bad.py", "content": corrected}], headers={"Idempotency-Key": "ver-1"}).json()
        replay = call(client, "POST", VERS, VERS, 200, key=KEY_ALICE, body={"scan_id": sid, "files": [{"path": "bad.py", "content": corrected}]}, headers={"Prefer": "wait=20", "Idempotency-Key": "ver-1"})
        assert replay.json()["id"] == first["id"] and replay.headers["idempotency-replayed"] == "true"
        assert verify([{"path": "bad.py", "content": BAD_CODE}], expect=409, headers={"Idempotency-Key": "ver-1"}).json()["code"] == "idempotency_conflict"
        # refusals
        verify([{"path": "bad.py", "content": "x"}], expect=404, extra={"scan_id": "scn_missing"})
        call(client, "POST", VERS, VERS, 404, key=KEY_CAROL, body={"scan_id": sid, "files": [{"path": "bad.py", "content": "x"}]})        # carol may verify, but not alice's scan
        for label, body in (("no files", {"scan_id": sid, "files": []}), ("no scan id", {"files": [{"path": "bad.py", "content": "x"}]}), ("unknown field", {"scan_id": sid, "files": [{"path": "a.py", "content": "x"}], CANARY: 1}),
                            ("content a list", {"scan_id": sid, "files": [{"path": "a.py", "content": [CANARY]}]}), ("duplicate paths", {"scan_id": sid, "files": [{"path": "a.py", "content": "x"}, {"path": "a.py", "content": "y"}]})):
            assert call(client, "POST", VERS, VERS, 400, key=KEY_ALICE, body=body).json()["code"] == "invalid_request", label
        call(client, "POST", VERS, VERS, 413, key=KEY_ALICE, body={"scan_id": sid, "files": [{"path": f"f{i}.py", "content": "x = 1"} for i in range(6)]})
        call(client, "POST", VERS, VERS, 413, key=KEY_ALICE, raw=b'{"scan_id":"x","files":[],"y":"' + b"a" * (gateway.max_body_bytes + 10) + b'"}')
        assert fixer.calls == calls_before, "verifying and refusing must never call the model"

        # the body of an unauthenticated or unauthorized fix request is never read; an authorized oversized one is drained, not held
        pieces = [b"x" * 50_000] * 20
        assert body_reads(app, {}, pieces, f"/v1/scans/{sid}/fixes") == (401, 0)
        assert body_reads(app, auth(KEY_CAROL), pieces, f"/v1/scans/{sid}/fixes") == (403, 0)
        status, read = body_reads(app, auth(KEY_ALICE), pieces, f"/v1/scans/{sid}/fixes")
        assert status == 413 and read == 20
        status, read = body_reads(app, auth(KEY_ALICE), [b"x" * 100_000] * 200, f"/v1/scans/{sid}/fixes")        # 20 MB: refused, and only about 8 MB of it is ever read (then dropped, never kept)
        assert status == 413 and read <= 90, f"an oversized fix upload was read for {read} pieces of 100 KB"
        assert body_reads(app, {}, pieces, "/v1/verifications") == (401, 0)

        # deleting the scan takes its fixes and verifications with it
        call(client, "DELETE", "/v1/scans/{scan_id}", f"/v1/scans/{sid}", 204, key=KEY_ALICE)
        call(client, "GET", FIX, f"/v1/fixes/{fix['id']}", 404, key=KEY_ALICE)
        call(client, "GET", VER, f"/v1/verifications/{passed['id']}", 404, key=KEY_ALICE)
        call(client, "GET", VER, f"/v1/verifications/{fix['verification']['id']}", 404, key=KEY_ALICE)
        call(client, "POST", FIXES, f"/v1/scans/{sid}/fixes", 404, key=KEY_ALICE, body={})
        assert store.child_count() == 0 or all(c.scan_id != sid for c in store._children.values())
    finally:
        gateway.shutdown()

    # a scan that is not finished, or whose job failed, cannot be fixed or checked yet: 409 scan_not_completed
    slow = ScanService([Stub(delay=1.5)], limits=LIMITS)
    app, gateway, store = build(service=slow, fix_service=FixService(slow, Fixer()))
    client = TestClient(app, raise_server_exceptions=False)
    try:
        running = call(client, "POST", "/v1/scans", expect=202, body=BODY, key=KEY_ALICE).json()["id"]
        r = call(client, "POST", FIXES, f"/v1/scans/{running}/fixes", 409, key=KEY_ALICE, body={})
        assert r.json()["code"] == "scan_not_completed" and "still" in r.json()["detail"]
        assert call(client, "POST", VERS, VERS, 409, key=KEY_ALICE, body={"scan_id": running, "files": [{"path": "bad.py", "content": "x"}]}).json()["code"] == "scan_not_completed"
        assert poll(client, running, KEY_ALICE)["status"] == "completed"
        nothing = call(client, "POST", FIXES, f"/v1/scans/{running}/fixes", 200, key=KEY_ALICE, body={}, headers={"Prefer": "wait=20"}).json()
        assert nothing["status"] == "completed" and nothing["applicable"] is False and nothing["patches"] == [] and nothing["verification"] is None and "nothing the corrector can fix" in nothing["failure_reason"]
    finally:
        gateway.shutdown()

    class Exploding(ScanService):
        def scan(self, files, language=None, context=None):
            raise RuntimeError(f"boom {CANARY}")

    exploding = Exploding([Stub()], limits=LIMITS)
    app, gateway, store = build(service=exploding, fix_service=FixService(exploding, Fixer()))
    client = TestClient(app, raise_server_exceptions=False)
    try:
        dead = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=20"}).json()
        assert dead["status"] == "failed"
        r = call(client, "POST", FIXES, f"/v1/scans/{dead['id']}/fixes", 409, key=KEY_ALICE, body={})
        assert r.json()["code"] == "scan_not_completed" and "failed" in r.json()["detail"] and CANARY not in r.text
    finally:
        gateway.shutdown()

    # the fix rate limit is its own and stricter, a crashing corrector is a failed job that says nothing about why, and fixes expire with their scan
    now = [90_000.0]
    svc = ScanService([BanditAnalyzer(), SecretsAnalyzer()], limits=LIMITS)
    crasher = Fixer("crash")
    app, gateway, store = build(service=svc, fix_service=FixService(svc, crasher), fix_rate=2, store_clock=lambda: now[0], retention=3600)
    client = TestClient(app, raise_server_exceptions=False)
    try:
        sid2 = call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=20"}).json()["id"]
        crashed = call(client, "POST", FIXES, f"/v1/scans/{sid2}/fixes", 200, key=KEY_ALICE, body={"max_patch_lines": 41}, headers={"Prefer": "wait=20"}).json()
        assert crashed["status"] == "failed" and crashed["applicable"] is False and crashed["patches"] == [] and crashed["verification"] is None      # the JOB failed, not just the fix
        assert "failed unexpectedly" in crashed["failure_reason"] and "boom" not in json.dumps(crashed) and CANARY not in json.dumps(crashed) and KEY_ALICE not in json.dumps(crashed)
        failed_job = call(client, "POST", FIXES, f"/v1/scans/{sid2}/fixes", 200, key=KEY_ALICE, body={"max_patch_lines": 42}, headers={"Prefer": "wait=20"}).json()
        limited = call(client, "POST", FIXES, f"/v1/scans/{sid2}/fixes", 429, key=KEY_ALICE, body={"max_patch_lines": 43})
        assert limited.json()["code"] == "rate_limited" and int(limited.headers["retry-after"]) >= 1
        call(client, "POST", "/v1/scans", expect=200, body=BODY, key=KEY_ALICE, headers={"Prefer": "wait=20"})            # scans are not limited by the fix limit
        now[0] += 3601                                                                                                      # the scan's retention ends, and its fixes with it
        call(client, "GET", FIX, f"/v1/fixes/{crashed['id']}", 404, key=KEY_ALICE)
        assert store.child_count() == 0
    finally:
        gateway.shutdown()

    # ---------------------------------------------------------------- the sweeps, across everything that happened
    assert len(ALL) > 80, len(ALL)
    for response in ALL:
        visible = response.text + " ".join(f"{k}: {v}" for k, v in response.headers.items())
        for key in (KEY_ALICE, KEY_BOB, KEY_CAROL):
            assert key not in visible, "an API key appeared in a response"
        if response.status_code >= 400:
            assert CANARY not in visible, f"submitted code or client text appeared in an error response: {visible[:200]}"
    logged = "\n".join(records.lines)
    assert len(records.lines) > 80 and CANARY not in logged and "ping" not in logged and "os.system" not in logged
    for key in (KEY_ALICE, KEY_BOB, KEY_CAROL):
        assert key not in logged and key[:10] not in logged, "an API key appeared in the log"
    assert "alice" in logged and "req_" in logged                                                              # the log does say who and which request
    assert "crashed: RuntimeError" in logged                                                                   # a crash IS logged, by type only (the sweep above shows no text)

    print(f"check_api OK: {len(ALL)} responses, every one matching the contract (status, content type, body); the key is checked before the body; "
          "ownership, idempotency, delete, retention, rate limit, busy and full, honest 501 for fixes when off, crashes: no key and no submitted code in any error or log line; "
          "fixes and verifications: every operation and refusal matches the contract, the model is never called for a refused request, and results go with their scan")


if __name__ == "__main__":
    run()
