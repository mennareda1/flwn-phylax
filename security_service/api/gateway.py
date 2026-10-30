"""
security_service/api/gateway.py

Every rule of the HTTP service, in plain Python: a request goes in, a Reply comes out. The web framework (app.py) only
translates between HTTP and this, so these rules are tested without a server.

The order of checks for an authenticated operation is fixed, and the order matters:
    1. the API key must be valid                 (401)   an unauthenticated caller learns nothing about the request
    2. the key must have the scope               (403)
    3. the caller must be within its rate limit  (429)
    4. the body must be small enough             (413)
    5. the body must be valid JSON and match the contract   (400)
    6. the request must be one the scanner accepts          (400, 413, 422)  -- so a bad request is answered at once and
       never becomes a failed job
    7. the work is queued; a retry with the same Idempotency-Key gets the original job back

Things this module never does: put submitted code, a key or a provider message into a response, an error or a log line;
run the submitted code; apply a fix. Scans run in a bounded pool of workers; `Prefer: wait=N` lets a caller wait up to
N seconds (never more than the configured maximum) for a result instead of polling.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Annotated, Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_service.adapters.bandit import BanditAnalyzer
from security_service.api.auth import KeyRing, Principal, bearer_token
from security_service.api.jobs import IdempotencyConflict, JobStore, ScanJob, StoreFull
from security_service.api.ratelimit import RateLimiter
from security_service.core.errors import api_problem, problem_for
from security_service.core.files import InvalidScanInput, SourceFile
from security_service.core.scan_service import ScanService

_WAIT = re.compile(r"(?:^|[,;\s])wait=(\d{1,3})(?:$|[,;\s])")
ANALYZER_CHECK_SECONDS = 30.0


# ---------------------------------------------------------------------- the request, as the contract writes it

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)      # unknown fields are errors, and no silent type coercion


class InputFileModel(_Strict):
    path: str = Field(min_length=1, max_length=500)
    content: str
    language: str | None = None


class ContextModel(_Strict):
    framework: str | None = Field(default=None, max_length=100)
    untrusted_inputs: list[Annotated[str, Field(max_length=200)]] | None = Field(default=None, max_length=50)
    purpose: str | None = Field(default=None, max_length=500)


class ScanRequestModel(_Strict):
    client_ref: str | None = Field(default=None, max_length=200)
    workspace_id: str | None = Field(default=None, max_length=200)
    language: str | None = None
    files: list[InputFileModel] = Field(min_length=1)
    context: ContextModel | None = None


def validation_detail(error: ValidationError) -> str:
    """What was wrong, by field name and rule only. Never the offending value, which may be code, and never the NAME of an
    unknown field, which the client chose."""
    problems = error.errors()
    shown = []
    for item in problems[:5]:
        if item["type"] == "extra_forbidden":
            where = ".".join(str(p) for p in item["loc"][:-1]) or "the request"
            shown.append(f"{where[:80]}: contains a field this contract does not define")
        else:
            shown.append(f"{'.'.join(str(p) for p in item['loc'])[:80] or 'body'}: {item['msg']}")
    return "; ".join(shown) + (f"; and {len(problems) - 5} more" if len(problems) > 5 else "")


# ---------------------------------------------------------------------- replies and errors

@dataclass
class Reply:
    status: int
    body: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)


class ApiError(Exception):
    def __init__(self, code: str, detail: str, headers: dict[str, str] | None = None):
        super().__init__(detail)
        self.code, self.detail, self.headers = code, detail, headers or {}

    def reply(self, request_id: str | None = None) -> Reply:
        body = api_problem(self.code, self.detail, request_id)
        return Reply(body["status"], body, dict(self.headers))


# ---------------------------------------------------------------------- the gateway

class Gateway:
    def __init__(self, scan_service: ScanService, keyring: KeyRing, store: JobStore, limiter: RateLimiter, *, workers: int = 4,
                 max_wait_seconds: int = 30, retention_hours: int = 24, max_queue: int = 200, max_body_bytes: int | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._scan, self._keys, self._store, self._limiter = scan_service, keyring, store, limiter
        self._workers, self._max_wait, self._retention_hours, self._max_queue = workers, max_wait_seconds, retention_hours, max_queue
        self.max_body_bytes = max_body_bytes or scan_service.limits.max_total_bytes * 2 + 100_000     # JSON escaping makes the body larger than the code
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")
        self._backlog = 0
        self._backlog_lock = threading.Lock()
        self._log = logging.getLogger("security_service.api")
        self._clock = clock
        self._analyzers_checked_at = float("-inf")
        self._analyzers_ok = True
        self._stop = threading.Event()
        self._sweeper: threading.Thread | None = None

    # ------------------------------------------------------------------ before anything else

    def authorize(self, authorization: str | None, scope: str | None) -> Principal:
        """Steps 1 to 3. `scope=None` means any valid key."""
        principal = self._keys.authenticate(bearer_token(authorization))
        if principal is None:
            raise ApiError("unauthorized", "A valid API key is required: send  Authorization: Bearer <key>.", {"WWW-Authenticate": "Bearer"})
        if scope is not None and not principal.allows(scope):
            raise ApiError("forbidden", f"This key does not have the '{scope}' scope.")
        allowed, wait = self._limiter.check(principal.name)
        if not allowed:
            raise ApiError("rate_limited", "Too many requests from this key; retry after the delay in Retry-After.", {"Retry-After": str(wait)})
        return principal

    # ------------------------------------------------------------------ scans

    def create_scan(self, principal: Principal, headers: Mapping[str, str], body: bytes) -> Reply:
        if len(body) > self.max_body_bytes:
            raise ApiError("payload_too_large", f"The request body is larger than this service accepts ({self.max_body_bytes} bytes).")
        key = headers.get("idempotency-key")
        if key is not None and not 1 <= len(key) <= 200:
            raise ApiError("invalid_request", "Idempotency-Key must be 1 to 200 characters.")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError("invalid_request", "The body is not valid JSON.") from None
        if not isinstance(data, dict):
            raise ApiError("invalid_request", "The body must be a JSON object.")
        try:
            request = ScanRequestModel.model_validate(data)
        except ValidationError as problem:
            raise ApiError("invalid_request", validation_detail(problem)) from None

        files = [SourceFile(f.path, f.content, f.language) for f in request.files]
        try:
            self._scan.validate_request(files, request.language)
        except InvalidScanInput as problem:
            answer = problem_for(problem)
            raise ApiError(answer["code"], answer["detail"]) from None

        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        with self._backlog_lock:
            busy = self._backlog >= self._workers + self._max_queue
        if busy:
            raise ApiError("provider_unavailable", "The service is busy; retry shortly.", {"Retry-After": "5"})
        try:
            job, replayed = self._store.create(principal.name, fingerprint, key, files, request.language,
                                               request.context.model_dump() if request.context else None, request.client_ref, request.workspace_id)
        except IdempotencyConflict:
            raise ApiError("idempotency_conflict", "This Idempotency-Key was already used with a different request.") from None
        except StoreFull:
            raise ApiError("provider_unavailable", "The service holds as many scans as it can; retry later.", {"Retry-After": "30"}) from None
        if not replayed:
            self._submit(job)

        headers_out: dict[str, str] = {"Idempotency-Replayed": "true"} if replayed else {}
        wanted = _WAIT.search(headers.get("prefer", ""))
        if wanted:
            seconds = min(int(wanted.group(1)), self._max_wait)
            job.done.wait(timeout=seconds)
            headers_out["Preference-Applied"] = f"wait={seconds}"
        if job.deleted:
            raise ApiError("not_found", "The scan was deleted while the request was waiting.")
        if job.done.is_set():
            return Reply(200, job.to_resource(), headers_out)
        return Reply(202, job.to_resource(), {**headers_out, "Location": f"/v1/scans/{job.id}"})

    def get_scan(self, principal: Principal, scan_id: str) -> Reply:
        job = self._store.get(scan_id, principal.name)
        if job is None:
            raise ApiError("not_found", "No such scan, or it has expired or been deleted.")
        return Reply(200, job.to_resource())

    def delete_scan(self, principal: Principal, scan_id: str) -> Reply:
        if not self._store.delete(scan_id, principal.name):
            raise ApiError("not_found", "No such scan, or it has expired or been deleted.")
        return Reply(204)

    # ------------------------------------------------------------------ operations whose feature is not built yet

    def not_available(self, what: str) -> Reply:
        raise ApiError("not_implemented", f"{what} is not available in this deployment; GET /v1/capabilities lists the available features.")

    def unknown(self, what: str) -> Reply:
        raise ApiError("not_found", f"No such {what}.")

    # ------------------------------------------------------------------ about the service

    def capabilities(self) -> Reply:
        body = self._scan.capabilities(retention_hours=self._retention_hours, max_wait_seconds=self._max_wait)
        body["features"] = {"fixes": False, "verifications": False}
        return Reply(200, body)

    def health(self) -> Reply:
        return Reply(200, {"status": "ok"})

    def ready(self) -> Reply:
        checks = {"job_store": "ok", "analyzers": "ok" if self._rules_engine_works() else "failing"}
        status = "ready" if all(v == "ok" for v in checks.values()) else "not_ready"
        return Reply(200 if status == "ready" else 503, {"status": status, "checks": checks})

    def _rules_engine_works(self) -> bool:
        """Can the rules engine actually run? Checked at most every 30 seconds, because it starts a subprocess."""
        now = self._clock()
        if now - self._analyzers_checked_at >= ANALYZER_CHECK_SECONDS:
            self._analyzers_ok = BanditAnalyzer().analyze("x = 1\n", "python").ok
            self._analyzers_checked_at = now
        return self._analyzers_ok

    # ------------------------------------------------------------------ running the work

    def _submit(self, job: ScanJob) -> None:
        with self._backlog_lock:
            self._backlog += 1
        self._pool.submit(self._run, job)

    def _run(self, job: ScanJob) -> None:
        try:
            files = job.files
            if files is None or not self._store.mark_running(job):          # deleted before it started
                return
            report = self._scan.scan(files, job.language, job.context)
            self._store.complete(job, report.to_dict())
        except Exception as problem:                                         # noqa: BLE001 - a crashed job must not crash the service
            self._log.error("scan job %s crashed: %s", job.id, type(problem).__name__)    # the type only: a message may contain code
            self._store.fail(job)
        finally:
            with self._backlog_lock:
                self._backlog -= 1

    def start_sweeper(self, interval_seconds: float = 60.0) -> None:
        """Remove expired jobs in the background, so retention holds even when nobody asks for them."""
        def loop():
            while not self._stop.wait(interval_seconds):
                removed = self._store.purge_expired()
                if removed:
                    self._log.info("retention: removed %d expired scan(s)", removed)

        self._sweeper = threading.Thread(target=loop, name="retention-sweeper", daemon=True)
        self._sweeper.start()

    def shutdown(self) -> None:
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)


def demo() -> None:
    from security_service.api.auth import parse_api_keys

    key_a, key_b = "Kq3vZ8nR2mXw5tYb7LcD9fGh1JpS4aUe", "Zx9wQ2eR5tY7uI1oP3aS6dF8gH0jK4lM"
    ring, problems = parse_api_keys(f"alice:scan+fix+read:{key_a},bob:read:{key_b}")
    assert not problems
    store = JobStore(retention_seconds=3600)
    gateway = Gateway(ScanService(), ring, store, RateLimiter(1000), workers=2, max_wait_seconds=10)
    alice = gateway.authorize(f"Bearer {key_a}", "scan")
    bad_code = json.dumps({"files": [{"path": "bad.py", "content": 'import os\nos.system("ping " + host)\n'}], "client_ref": "wi-1"}).encode()

    def refused(call, code):
        try:
            call()
            raise AssertionError(f"expected {code}")
        except ApiError as problem:
            assert problem.code == code, (problem.code, problem.detail)
            return problem

    try:
        # the order of the checks: no key is 401 even for a body that is also wrong; a read-only key cannot scan
        refused(lambda: gateway.authorize(None, "scan"), "unauthorized")
        refused(lambda: gateway.authorize("Bearer wrong-key-wrong-key-wrong-key", "scan"), "unauthorized")
        refused(lambda: gateway.authorize(f"Bearer {key_b}", "scan"), "forbidden")
        assert gateway.authorize(f"Bearer {key_b}", None).name == "bob"                  # any valid key may read capabilities

        # wait for the result: 200 with the finished scan; no wait: 202 with a Location, and the result arrives by polling
        done = gateway.create_scan(alice, {"prefer": "wait=10"}, bad_code)
        assert done.status == 200 and done.body["status"] == "completed" and done.body["report"]["decision"] == "block"
        assert done.headers["Preference-Applied"] == "wait=10" and done.body["client_ref"] == "wi-1"
        queued = gateway.create_scan(alice, {}, bad_code)
        assert queued.status in (200, 202) and (queued.status == 200 or queued.headers["Location"] == f"/v1/scans/{queued.body['id']}")
        for _ in range(100):
            polled = gateway.get_scan(alice, queued.body["id"])
            if polled.body["status"] == "completed":
                break
            time.sleep(0.1)
        assert polled.body["status"] == "completed" and polled.body["report"]["decision"] == "block"

        # idempotency: the same key and request is the SAME scan; the same key with a different request is a conflict
        first = gateway.create_scan(alice, {"idempotency-key": "k-1", "prefer": "wait=10"}, bad_code)
        again = gateway.create_scan(alice, {"idempotency-key": "k-1", "prefer": "wait=10"}, bad_code)
        assert again.body["id"] == first.body["id"] and again.headers["Idempotency-Replayed"] == "true" and "Idempotency-Replayed" not in first.headers
        refused(lambda: gateway.create_scan(alice, {"idempotency-key": "k-1"}, json.dumps({"files": [{"path": "x.py", "content": "x = 1"}]}).encode()), "idempotency_conflict")
        refused(lambda: gateway.create_scan(alice, {"idempotency-key": ""}, bad_code), "invalid_request")

        # every way a request can be wrong is answered at once, and no answer repeats what was sent
        secret = "SuperSecretCode123"
        for label, body, code in (
            ("not json", b"{not json", "invalid_request"),
            ("a list", b"[1, 2]", "invalid_request"),
            ("no files", b'{"files": []}', "invalid_request"),
            ("unknown field", json.dumps({"files": [{"path": "a.py", "content": "x"}], secret: 1}).encode(), "invalid_request"),
            ("wrong type", json.dumps({"files": [{"path": "a.py", "content": 12345}]}).encode(), "invalid_request"),
            ("files is a string holding code", json.dumps({"files": secret}).encode(), "invalid_request"),
            ("content is a list holding code", json.dumps({"files": [{"path": "a.py", "content": [secret]}]}).encode(), "invalid_request"),
            ("language is an object holding code", json.dumps({"language": {"x": secret}, "files": [{"path": "a.py", "content": "x"}]}).encode(), "invalid_request"),
            ("path is too long and holds code", json.dumps({"files": [{"path": secret * 100, "content": "x"}]}).encode(), "invalid_request"),
            ("content as a number", json.dumps({"files": [{"path": "a.py", "content": 5}], "client_ref": secret}).encode(), "invalid_request"),
            ("duplicate paths", json.dumps({"files": [{"path": "a.py", "content": "x"}, {"path": "a.py", "content": "y"}]}).encode(), "invalid_request"),
            ("unsupported language", json.dumps({"language": "cobol", "files": [{"path": "a.cob", "content": secret}]}).encode(), "unsupported_language"),
            ("too big", b"{" + b" " * (gateway.max_body_bytes + 1), "payload_too_large"),
        ):
            problem = refused(lambda body=body: gateway.create_scan(alice, {}, body), code)
            assert secret not in problem.detail and "ping" not in problem.detail, f"{label}: the answer repeats what was sent"
        assert len(store) == 3                                                           # none of the bad requests became a job

        # OWNERSHIP: bob (read-only) cannot see alice's scan; alice can; deleting removes it for good
        bob = gateway.authorize(f"Bearer {key_b}", "read")
        refused(lambda: gateway.get_scan(bob, first.body["id"]), "not_found")
        refused(lambda: gateway.delete_scan(bob, first.body["id"]), "not_found")
        assert gateway.get_scan(alice, first.body["id"]).body["status"] == "completed"
        assert gateway.delete_scan(alice, first.body["id"]).status == 204
        refused(lambda: gateway.get_scan(alice, first.body["id"]), "not_found")
        refused(lambda: gateway.delete_scan(alice, first.body["id"]), "not_found")

        # features that are not built answer honestly
        refused(lambda: gateway.not_available("Fixes"), "not_implemented")
        caps = gateway.capabilities().body
        assert caps["features"] == {"fixes": False, "verifications": False} and caps["limits"]["max_wait_seconds"] == 10 and caps["retention_hours"] == 24
        assert gateway.health().body == {"status": "ok"} and gateway.ready().body == {"status": "ready", "checks": {"job_store": "ok", "analyzers": "ok"}}

        # a crashed job is a failed job, and says nothing about what crashed it
        class Crashing(ScanService):
            def scan(self, files, language=None, context=None):
                raise RuntimeError(f"boom with {secret}")

        crashy = Gateway(Crashing(), ring, JobStore(3600), RateLimiter(1000), workers=1)
        try:
            crashed = crashy.create_scan(alice, {"prefer": "wait=5"}, bad_code)
            assert crashed.status == 200 and crashed.body["status"] == "failed" and crashed.body["report"] is None and secret not in json.dumps(crashed.body)
        finally:
            crashy.shutdown()
    finally:
        gateway.shutdown()

    print("api.gateway OK: check order, wait or poll, idempotency, every bad request answered at once without echoing it, ownership, delete, honest 501, crashes leak nothing")


if __name__ == "__main__":
    demo()
