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

Fixes and verifications work the same way and follow the same order of checks, with these differences:
  - A FIX asks the corrector (a model call per file, which costs money), so it has its own, stricter rate limit and its own small pool of
    workers: slow model calls cannot starve ordinary scans, and a flood of fix requests cannot become an unbounded bill. A scan may hold only a
    few fix requests. Nothing is ever applied: `applicable` is true only when the service's own verification passed.
  - A VERIFICATION checks a correction the CALLER wrote. It needs no model, only the scanner.
  - Both need a COMPLETED scan of the same caller (409 `scan_not_completed` otherwise; another caller's scan is "not found").
  - They live as long as their scan and are removed with it.
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
from security_service.api.jobs import ChildJob, IdempotencyConflict, JobStore, ScanJob, StoreFull, TooManyFixes
from security_service.api.ratelimit import RateLimiter
from security_service.core.errors import api_problem, problem_for
from security_service.core.files import InvalidScanInput, SourceFile
from security_service.core.fix_service import FixService
from security_service.core.scan_service import ScanService
from security_service.core.verification import VerificationService

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


class FixRequestModel(_Strict):
    finding_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = Field(default=None, min_length=1, max_length=100)
    max_patch_lines: int | None = Field(default=None, ge=1, le=200)


class VerificationRequestModel(_Strict):
    scan_id: str = Field(min_length=1, max_length=100)
    client_ref: str | None = Field(default=None, max_length=200)
    files: list[InputFileModel] = Field(min_length=1)


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
                 clock: Callable[[], float] = time.monotonic, fix_service: FixService | None = None, verifier: VerificationService | None = None,
                 fix_workers: int = 2, fix_max_queue: int = 20, fix_limiter: RateLimiter | None = None):
        self._scan, self._keys, self._store, self._limiter = scan_service, keyring, store, limiter
        self._fix_service = fix_service
        self._verifier = verifier or VerificationService(scan_service)
        self._fix_limiter = fix_limiter or RateLimiter(10)
        self._fix_workers, self._fix_max_queue = fix_workers, fix_max_queue
        self._fix_pool = ThreadPoolExecutor(max_workers=fix_workers, thread_name_prefix="fix") if fix_service is not None else None
        self._fix_backlog = 0
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

    # ------------------------------------------------------------------ fixes and verifications

    @staticmethod
    def _json_body(body: bytes, limit: int, allow_empty: bool = False) -> dict:
        if len(body) > limit:
            raise ApiError("payload_too_large", f"The request body is larger than this service accepts ({limit} bytes).")
        if allow_empty and not body.strip():
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError("invalid_request", "The body is not valid JSON.") from None
        if not isinstance(data, dict):
            raise ApiError("invalid_request", "The body must be a JSON object.")
        return data

    @staticmethod
    def _idempotency_key(headers: Mapping[str, str]) -> str | None:
        key = headers.get("idempotency-key")
        if key is not None and not 1 <= len(key) <= 200:
            raise ApiError("invalid_request", "Idempotency-Key must be 1 to 200 characters.")
        return key

    def _completed_scan(self, principal: Principal, scan_id: str) -> ScanJob:
        job = self._store.get(scan_id, principal.name)
        if job is None:
            raise ApiError("not_found", "No such scan, or it has expired or been deleted.")
        if job.status == "failed":
            raise ApiError("scan_not_completed", "The scan's job failed, so there is nothing to fix or check.")
        if job.status != "completed" or job.findings is None or job.files is None:
            raise ApiError("scan_not_completed", f"The scan is still {job.status}; ask again once its status is completed.")
        return job

    def _new_child(self, kind: str, principal: Principal, scan_id: str, fingerprint: str, key: str | None) -> tuple[ChildJob, bool]:
        try:
            return self._store.create_child(kind, principal.name, scan_id, fingerprint, key)
        except IdempotencyConflict:
            raise ApiError("idempotency_conflict", "This Idempotency-Key was already used with a different request.") from None
        except StoreFull:
            raise ApiError("provider_unavailable", "The service holds as many results as it can; retry later.", {"Retry-After": "30"}) from None
        except TooManyFixes:
            raise ApiError("fix_limit_reached", "This scan already has as many fix requests as one scan may have; each costs a model call. Scan the code again if you need more.") from None
        except LookupError:
            raise ApiError("not_found", "No such scan, or it has expired or been deleted.") from None

    def _child_reply(self, child: ChildJob, headers: Mapping[str, str], replayed: bool, location: str) -> Reply:
        headers_out: dict[str, str] = {"Idempotency-Replayed": "true"} if replayed else {}
        wanted = _WAIT.search(headers.get("prefer", ""))
        if wanted:
            seconds = min(int(wanted.group(1)), self._max_wait)
            child.done.wait(timeout=seconds)
            headers_out["Preference-Applied"] = f"wait={seconds}"
        if child.deleted:
            raise ApiError("not_found", "The scan was deleted while the request was waiting.")
        if child.done.is_set():
            return Reply(200, child.to_resource(), headers_out)
        return Reply(202, child.to_resource(), {**headers_out, "Location": location})

    def create_fix(self, principal: Principal, scan_id: str, headers: Mapping[str, str], body: bytes) -> Reply:
        if self._fix_service is None:
            raise ApiError("not_implemented", "Fixes are not available in this deployment; GET /v1/capabilities lists the available features.")
        allowed, wait = self._fix_limiter.check(principal.name)
        if not allowed:
            raise ApiError("rate_limited", "Too many fix requests from this key (each costs a model call); retry after the delay in Retry-After.", {"Retry-After": str(wait)})
        data = self._json_body(body, 65_536, allow_empty=True)
        try:
            request = FixRequestModel.model_validate(data)
        except ValidationError as problem:
            raise ApiError("invalid_request", validation_detail(problem)) from None
        key = self._idempotency_key(headers)
        scan = self._completed_scan(principal, scan_id)
        if request.finding_ids:
            known = {f.id for f in scan.findings}
            missing = [i for i in request.finding_ids if i not in known]
            if missing:
                raise ApiError("invalid_request", f"{len(missing)} finding id(s) are not in this scan.")
        fingerprint = hashlib.sha256(json.dumps({"scan": scan.id, "body": data}, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        with self._backlog_lock:
            busy = self._fix_backlog >= self._fix_workers + self._fix_max_queue
        if busy:
            raise ApiError("provider_unavailable", "The service is busy with fixes; retry shortly.", {"Retry-After": "10"})
        child, replayed = self._new_child("fix", principal, scan.id, fingerprint, key)
        if not replayed:
            with self._backlog_lock:
                self._fix_backlog += 1
            self._fix_pool.submit(self._run_fix, child, scan.id, principal.name, list(scan.files), list(scan.findings), request.finding_ids, request.max_patch_lines or 40)
        return self._child_reply(child, headers, replayed, f"/v1/fixes/{child.id}")

    def create_verification(self, principal: Principal, headers: Mapping[str, str], body: bytes) -> Reply:
        data = self._json_body(body, self.max_body_bytes)
        key = self._idempotency_key(headers)
        try:
            request = VerificationRequestModel.model_validate(data)
        except ValidationError as problem:
            raise ApiError("invalid_request", validation_detail(problem)) from None
        scan = self._completed_scan(principal, request.scan_id)
        corrected = [SourceFile(f.path, f.content, f.language) for f in request.files]
        try:
            self._scan.validate_request(corrected, None)
        except InvalidScanInput as problem:
            answer = problem_for(problem)
            raise ApiError(answer["code"], answer["detail"]) from None
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        with self._backlog_lock:
            busy = self._backlog >= self._workers + self._max_queue
        if busy:
            raise ApiError("provider_unavailable", "The service is busy; retry shortly.", {"Retry-After": "5"})
        child, replayed = self._new_child("verification", principal, scan.id, fingerprint, key)
        if not replayed:
            with self._backlog_lock:
                self._backlog += 1
            self._pool.submit(self._run_verification, child, list(scan.files), list(scan.findings), corrected)
        return self._child_reply(child, headers, replayed, f"/v1/verifications/{child.id}")

    def get_fix(self, principal: Principal, fix_id: str) -> Reply:
        child = self._store.get_child("fix", fix_id, principal.name)
        if child is None:
            raise ApiError("not_found", "No such fix, or it has expired or been deleted.")
        return Reply(200, child.to_resource())

    def get_verification(self, principal: Principal, verification_id: str) -> Reply:
        child = self._store.get_child("verification", verification_id, principal.name)
        if child is None:
            raise ApiError("not_found", "No such verification, or it has expired or been deleted.")
        return Reply(200, child.to_resource())

    # ------------------------------------------------------------------ about the service

    def capabilities(self) -> Reply:
        body = self._scan.capabilities(retention_hours=self._retention_hours, max_wait_seconds=self._max_wait)
        body["features"] = {"fixes": self._fix_service is not None, "verifications": True}
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
            self._store.complete(job, report.to_dict(), report.findings)
        except Exception as problem:                                         # noqa: BLE001 - a crashed job must not crash the service
            self._log.error("scan job %s crashed: %s", job.id, type(problem).__name__)    # the type only: a message may contain code
            self._store.fail(job)
        finally:
            with self._backlog_lock:
                self._backlog -= 1

    def _run_fix(self, child: ChildJob, scan_id: str, owner: str, files: list, findings: list, finding_ids: list | None, limit: int) -> None:
        try:
            if not self._store.mark_child_running(child):
                return
            result = self._fix_service.fix(files, findings, finding_ids, limit)
            part = result.to_dict()
            if result.verification is not None:                       # the verification embedded in the fix can also be fetched by its own id
                embedded = self._store.add_verification(owner, scan_id, result.verification.to_dict())
                if embedded is None:                                   # the scan was deleted meanwhile: its children are gone too
                    self._store.fail_child(child)
                    return
                part["verification"] = embedded
            self._store.complete_child(child, part)
        except Exception as problem:                                   # noqa: BLE001 - a crashed job must not crash the service
            self._log.error("fix job %s crashed: %s", child.id, type(problem).__name__)       # the type only: a message may contain code
            self._store.fail_child(child)
        finally:
            with self._backlog_lock:
                self._fix_backlog -= 1

    def _run_verification(self, child: ChildJob, originals: list, findings: list, corrected: list) -> None:
        try:
            if not self._store.mark_child_running(child):
                return
            result = self._verifier.verify(originals, corrected, findings, None, 200)
            self._store.complete_child(child, result.to_dict())
        except Exception as problem:                                   # noqa: BLE001
            self._log.error("verification job %s crashed: %s", child.id, type(problem).__name__)
            self._store.fail_child(child)
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
        if self._fix_pool is not None:
            self._fix_pool.shutdown(wait=False, cancel_futures=True)


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

        # fixes are off in this deployment (no fix service): honest 501, and the capabilities say so; verifications are on
        refused(lambda: gateway.create_fix(alice, "scn_x", {}, b"{}"), "not_implemented")
        caps = gateway.capabilities().body
        assert caps["features"] == {"fixes": False, "verifications": True} and caps["limits"]["max_wait_seconds"] == 10 and caps["retention_hours"] == 24
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

    # ---------------------------------------------------------------- fixes and verifications, with scripted engines and a scripted corrector
    import re

    from security_service.core.fix_service import FixService
    from security_service.core.patching import make_unified_diff
    from security_service.core.schema import Confidence, EvidenceTier, Finding, Severity
    from security_service.ports.analyzer import AnalyzerResult
    from security_service.ports.corrector import Patch

    class Rules:
        role, name, languages = "analyzer", "rules", ("python",)

        def analyze(self, code, language):
            import time as _t
            if "# SLOW" in code:
                _t.sleep(1.2)
            return AnalyzerResult(analyzer="rules", findings=[
                Finding("command_injection", Severity.HIGH, Confidence.HIGH, EvidenceTier.STATIC_RULE, ["rules"], "B605", None, number, line.strip(), "a shell call", "avoid it")
                for number, line in enumerate(code.split("\n"), start=1) if re.search(r"os\.system\(", line)])

    class Fixer:
        role, name = "corrector", "scripted"
        mode = "good"

        def propose_fix(self, file, findings, constraints):
            if self.mode == "crash":
                raise RuntimeError("boom with a canary")
            new = file.content.replace("os.system(h)", 'subprocess.run([h], check=True)').replace("import os\n", "import os\nimport subprocess\n")
            return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, new), "Replaced the shell call.")]

    fixer = Fixer()
    svc = ScanService([Rules()])
    store2 = JobStore(retention_seconds=3600)
    full = Gateway(svc, ring, store2, RateLimiter(1000), workers=2, max_wait_seconds=10, fix_service=FixService(svc, fixer), fix_limiter=RateLimiter(100))
    try:
        alice2 = full.authorize(f"Bearer {key_a}", "fix")
        bob2 = full.authorize(f"Bearer {key_b}", "read")
        refused(lambda: full.authorize(f"Bearer {key_b}", "fix"), "forbidden")                     # a read-only key may not ask for fixes
        assert full.capabilities().body["features"] == {"fixes": True, "verifications": True}
        source = 'import os\n\ndef run(h):\n    os.system(h)\n'
        scan_body = json.dumps({"files": [{"path": "a.py", "content": source}]}).encode()
        scan = full.create_scan(alice2, {"prefer": "wait=10"}, scan_body).body
        assert scan["status"] == "completed" and scan["report"]["findings"][0]["id"] == "f1"

        # a fix: wait for it, get the patches and the embedded verification, fetch both again by id, and nobody else can
        fix = full.create_fix(alice2, scan["id"], {"prefer": "wait=10", "idempotency-key": "fx-1"}, b"{}")
        resource = fix.body
        assert fix.status == 200 and resource["status"] == "completed" and resource["applicable"] is True and resource["failure_reason"] is None and resource["unfixed"] == []
        assert resource["patches"][0]["path"] == "a.py" and resource["patches"][0]["finding_ids"] == ["f1"] and "+import subprocess" in resource["patches"][0]["unified_diff"]
        verification = resource["verification"]
        assert verification["id"].startswith("ver_") and verification["outcome"] == "passed" and verification["scan_id"] == scan["id"] and verification["resolved_finding_ids"] == ["f1"]
        assert full.get_fix(alice2, resource["id"]).body == resource and full.get_verification(alice2, verification["id"]).body == verification
        refused(lambda: full.get_fix(bob2, resource["id"]), "not_found")
        refused(lambda: full.get_verification(bob2, verification["id"]), "not_found")
        refused(lambda: full.get_fix(alice2, verification["id"]), "not_found")                       # a verification id is not a fix id

        # a retry is the same fix (and asks the corrector nothing more); the same key with another body is a conflict
        again = full.create_fix(alice2, scan["id"], {"prefer": "wait=10", "idempotency-key": "fx-1"}, b"{}")
        assert again.body["id"] == resource["id"] and again.headers["Idempotency-Replayed"] == "true"
        refused(lambda: full.create_fix(alice2, scan["id"], {"idempotency-key": "fx-1"}, b'{"max_patch_lines": 5}'), "idempotency_conflict")

        # bad requests: unknown finding, wrong types, unknown fields, an empty id list, a limit out of range, a scan that is not there
        for label, body, code in (("unknown finding id", b'{"finding_ids": ["f9"]}', "invalid_request"), ("ids as a string", b'{"finding_ids": "f1"}', "invalid_request"),
                                  ("empty ids", b'{"finding_ids": []}', "invalid_request"), ("limit 0", b'{"max_patch_lines": 0}', "invalid_request"),
                                  ("limit 201", b'{"max_patch_lines": 201}', "invalid_request"), ("unknown field", b'{"surprise": 1}', "invalid_request"),
                                  ("not json", b"{nope", "invalid_request"), ("a list", b"[1]", "invalid_request")):
            refused(lambda body=body: full.create_fix(alice2, scan["id"], {}, body), code)
        refused(lambda: full.create_fix(alice2, "scn_missing", {}, b"{}"), "not_found")
        refused(lambda: full.create_fix(bob2, scan["id"], {}, b"{}"), "not_found")                    # another caller's scan is not found, never "forbidden"
        refused(lambda: full.create_fix(alice2, scan["id"], {}, b" " * 70_000), "payload_too_large")
        assert full.create_fix(alice2, scan["id"], {"prefer": "wait=10"}, b"").status == 200          # an empty body is an empty request: fix everything at medium or above

        # the size limit reaches the verifier: a one-line limit makes a 3-line patch fail verification, so it is not applicable (but shown)
        small = full.create_fix(alice2, scan["id"], {"prefer": "wait=10"}, b'{"max_patch_lines": 1}').body
        assert small["applicable"] is False and small["verification"]["outcome"] == "failed" and small["patches"] and "limit 1" in small["failure_reason"]

        # a scan may hold only a few fix requests (each costs a model call): the sixth is refused
        for index in range(2):                                                                       # fx-1, empty-body and limit-1 above are three; two more make five
            full.create_fix(alice2, scan["id"], {"prefer": "wait=10"}, json.dumps({"max_patch_lines": 10 + index}).encode())
        refused(lambda: full.create_fix(alice2, scan["id"], {}, b'{"max_patch_lines": 99}'), "fix_limit_reached")

        # a scan that is not finished, or that failed, cannot be fixed or checked yet: 409 scan_not_completed
        slow = full.create_scan(alice2, {}, json.dumps({"files": [{"path": "s.py", "content": source + "# SLOW\n"}]}).encode()).body
        problem = refused(lambda: full.create_fix(alice2, slow["id"], {}, b"{}"), "scan_not_completed")
        assert "still" in problem.detail
        refused(lambda: full.create_verification(alice2, {}, json.dumps({"scan_id": slow["id"], "files": [{"path": "s.py", "content": "x = 1\n"}]}).encode()), "scan_not_completed")

        # a crashing corrector is a failed job that says nothing about why
        fixer.mode = "crash"
        second_scan = full.create_scan(alice2, {"prefer": "wait=10"}, scan_body.replace(b"def run", b"def go")).body
        crashed = full.create_fix(alice2, second_scan["id"], {"prefer": "wait=10"}, b"{}").body
        assert crashed["status"] == "failed" and crashed["patches"] == [] and crashed["applicable"] is False and "canary" not in json.dumps(crashed) and "boom" not in json.dumps(crashed)
        fixer.mode = "good"

        # verifying a correction the CALLER wrote: no model needed
        def verify(scan_id, content, path="a.py", **extra):
            return full.create_verification(alice2, {"prefer": "wait=10"}, json.dumps({"scan_id": scan_id, "files": [{"path": path, "content": content}], **extra}).encode())

        passed = verify(scan["id"], 'import os\nimport subprocess\n\ndef run(h):\n    subprocess.run([h], check=True)\n', client_ref="mine").body
        assert passed["status"] == "completed" and passed["outcome"] == "passed" and passed["resolved_finding_ids"] == ["f1"] and passed["new_findings"] == []
        assert [c["name"] for c in passed["checks"]] == ["scope", "syntax", "patch_size", "rescan"] and full.get_verification(alice2, passed["id"]).body == passed
        still = verify(scan["id"], source + "# still unsafe\n").body
        assert still["outcome"] == "failed" and any(c["name"] == "rescan" and c["result"] == "fail" for c in still["checks"])
        stranger = verify(scan["id"], source.replace("os.system(h)", "print(h)"), path="b.py").body
        assert stranger["outcome"] == "failed" and stranger["checks"][0]["name"] == "scope" and stranger["checks"][0]["result"] == "fail"
        big = verify(scan["id"], "import os\n\ndef run(h):\n" + "".join(f"    x{i} = {i}\n" for i in range(60))).body       # 60 changed lines: over the fix limit of 40, within the 200 allowed here
        assert next(c for c in big["checks"] if c["name"] == "patch_size")["result"] == "pass"
        refused(lambda: verify("scn_missing", "x = 1\n"), "not_found")
        refused(lambda: full.create_verification(bob2, {}, json.dumps({"scan_id": scan["id"], "files": [{"path": "a.py", "content": "x"}]}).encode()), "not_found")
        for label, body in (("no files", {"scan_id": scan["id"], "files": []}), ("no scan id", {"files": [{"path": "a.py", "content": "x"}]}), ("unknown field", {"scan_id": scan["id"], "files": [{"path": "a.py", "content": "x"}], "x": 1}),
                            ("content a number", {"scan_id": scan["id"], "files": [{"path": "a.py", "content": 5}]}), ("duplicate paths", {"scan_id": scan["id"], "files": [{"path": "a.py", "content": "x"}, {"path": "a.py", "content": "y"}]})):
            refused(lambda body=body: full.create_verification(alice2, {}, json.dumps(body).encode()), "invalid_request")
        refused(lambda: full.create_verification(alice2, {}, b"{" + b" " * (full.max_body_bytes + 1)), "payload_too_large")
        replay_a = full.create_verification(alice2, {"prefer": "wait=10", "idempotency-key": "v-1"}, json.dumps({"scan_id": scan["id"], "files": [{"path": "a.py", "content": "x = 1\n"}]}).encode())
        replay_b = full.create_verification(alice2, {"prefer": "wait=10", "idempotency-key": "v-1"}, json.dumps({"scan_id": scan["id"], "files": [{"path": "a.py", "content": "x = 1\n"}]}).encode())
        assert replay_b.body["id"] == replay_a.body["id"] and replay_b.headers["Idempotency-Replayed"] == "true"
        refused(lambda: full.create_verification(alice2, {"idempotency-key": "v-1"}, json.dumps({"scan_id": scan["id"], "files": [{"path": "a.py", "content": "y = 2\n"}]}).encode()), "idempotency_conflict")

        # deleting the scan removes its fixes and verifications with it, and what they held
        assert store2.child_count() >= 8
        full.delete_scan(alice2, scan["id"])
        refused(lambda: full.get_fix(alice2, resource["id"]), "not_found")
        refused(lambda: full.get_verification(alice2, verification["id"]), "not_found")
        refused(lambda: full.get_verification(alice2, passed["id"]), "not_found")
    finally:
        full.shutdown()

    # the fix rate limit is its own, stricter one: the third request in a minute is refused, and scans are unaffected
    limited = Gateway(svc, ring, JobStore(3600), RateLimiter(1000), workers=2, max_wait_seconds=10, fix_service=FixService(svc, Fixer()), fix_limiter=RateLimiter(2))
    try:
        who = limited.authorize(f"Bearer {key_a}", "fix")
        the_scan = limited.create_scan(who, {"prefer": "wait=10"}, scan_body).body
        limited.create_fix(who, the_scan["id"], {"prefer": "wait=10"}, b'{"max_patch_lines": 11}')
        limited.create_fix(who, the_scan["id"], {"prefer": "wait=10"}, b'{"max_patch_lines": 12}')
        problem = refused(lambda: limited.create_fix(who, the_scan["id"], {}, b'{"max_patch_lines": 13}'), "rate_limited")
        assert "Retry-After" in problem.headers and int(problem.headers["Retry-After"]) >= 1
        assert limited.create_scan(who, {"prefer": "wait=10"}, scan_body.replace(b"def run", b"def other")).status == 200
    finally:
        limited.shutdown()

    print("api.gateway OK: check order, wait or poll, idempotency, every bad request answered at once without echoing it, ownership, delete, honest 501, crashes leak nothing")


if __name__ == "__main__":
    demo()
