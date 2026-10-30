"""
security_service/api/jobs.py

Where scans live while the service runs: submitted code, status and results, kept in MEMORY ONLY, never written to disk.
(A restart forgets everything; that is stated in the README, and a persistent store is a later step.)

What it guarantees:
  - OWNERSHIP: a job belongs to the caller who created it. Anyone else asking for it gets "not found", never "forbidden",
    so a caller cannot even learn that another caller's job exists.
  - IDEMPOTENCY: the same caller sending the same Idempotency-Key and the same request gets the ORIGINAL job back instead
    of a second one; the same key with a different request is a conflict. Keys are scoped per caller.
  - RETENTION: a job, with its code and its results, disappears when its retention window ends (checked on every access
    and by a periodic sweep). DELETE removes it at once, and a scan that finishes after being deleted is thrown away.
  - BOUNDS: at most `max_jobs` are held, so a flood of requests cannot use up all memory.

A job's status describes the JOB, not the code: `completed` means the scan ran, even if its decision is scan_failed.
`failed` means the job itself crashed.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from security_service.core.files import SourceFile


class IdempotencyConflict(Exception):
    """The Idempotency-Key was used before, with a different request."""


class StoreFull(Exception):
    """The store holds as many jobs as it is allowed to."""


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ScanJob:
    id: str
    owner: str
    created_at: float
    expires_at: float
    fingerprint: str
    idempotency_key: str | None
    client_ref: str | None
    workspace_id: str | None
    language: str | None
    context: dict | None
    files: list[SourceFile] | None          # kept until the job expires or is deleted: the fix step will need them
    status: str = "queued"                  # queued | running | completed | failed
    completed_at: float | None = None
    report: dict | None = None
    deleted: bool = False
    done: threading.Event = field(default_factory=threading.Event)

    def to_resource(self) -> dict:
        """The `Scan` object of the contract."""
        return {
            "id": self.id,
            "status": self.status,
            "created_at": iso(self.created_at),
            "completed_at": iso(self.completed_at) if self.completed_at is not None else None,
            "client_ref": self.client_ref,
            "report": self.report if self.status == "completed" else None,
        }


class JobStore:
    def __init__(self, retention_seconds: float, max_jobs: int = 5000, clock: Callable[[], float] = time.time):
        if retention_seconds <= 0 or max_jobs < 1:
            raise ValueError("retention_seconds and max_jobs must be positive")
        self._retention = retention_seconds
        self._max_jobs = max_jobs
        self._clock = clock
        self._jobs: dict[str, ScanJob] = {}
        self._keys: dict[tuple[str, str], str] = {}     # (owner, Idempotency-Key) -> job id
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._jobs)

    # ------------------------------------------------------------------ creating and finding

    def create(self, owner: str, fingerprint: str, idempotency_key: str | None, files: list[SourceFile],
               language: str | None, context: dict | None, client_ref: str | None, workspace_id: str | None) -> tuple[ScanJob, bool]:
        """Returns (job, replayed). replayed=True means an earlier identical request already made this job."""
        with self._lock:
            self._purge_locked()
            if idempotency_key:
                earlier = self._jobs.get(self._keys.get((owner, idempotency_key), ""))
                if earlier is not None:
                    if earlier.fingerprint != fingerprint:
                        raise IdempotencyConflict()
                    return earlier, True
            if len(self._jobs) >= self._max_jobs:
                raise StoreFull()
            now = self._clock()
            job = ScanJob(id=f"scn_{secrets.token_hex(8)}", owner=owner, created_at=now, expires_at=now + self._retention,
                          fingerprint=fingerprint, idempotency_key=idempotency_key, client_ref=client_ref, workspace_id=workspace_id,
                          language=language, context=context, files=list(files))
            self._jobs[job.id] = job
            if idempotency_key:
                self._keys[(owner, idempotency_key)] = job.id
            return job, False

    def get(self, job_id: str, owner: str) -> ScanJob | None:
        with self._lock:
            self._purge_locked()
            job = self._jobs.get(job_id)
            return job if job is not None and job.owner == owner else None

    # ------------------------------------------------------------------ the job's life

    def mark_running(self, job: ScanJob) -> bool:
        with self._lock:
            if job.deleted:
                return False
            job.status = "running"
            return True

    def complete(self, job: ScanJob, report: dict) -> None:
        with self._lock:
            if not job.deleted:                 # a scan that finishes after DELETE is thrown away
                job.report, job.status, job.completed_at = report, "completed", self._clock()
            job.done.set()

    def fail(self, job: ScanJob) -> None:
        with self._lock:
            if not job.deleted:
                job.status, job.completed_at = "failed", self._clock()
            job.done.set()

    # ------------------------------------------------------------------ ending

    def delete(self, job_id: str, owner: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner != owner or job.deleted:
                return False
            self._drop_locked(job)
            return True

    def purge_expired(self) -> int:
        with self._lock:
            return self._purge_locked()

    def _purge_locked(self) -> int:
        now = self._clock()
        expired = [job for job in self._jobs.values() if job.expires_at <= now]
        for job in expired:
            self._drop_locked(job)
        return len(expired)

    def _drop_locked(self, job: ScanJob) -> None:
        job.deleted = True
        job.files = None                        # the submitted code goes with the job
        job.report = None
        self._jobs.pop(job.id, None)
        if job.idempotency_key:
            self._keys.pop((job.owner, job.idempotency_key), None)
        job.done.set()                          # release anyone still waiting on it


def demo() -> None:
    now = [10_000.0]
    store = JobStore(retention_seconds=3600, max_jobs=3, clock=lambda: now[0])
    files = [SourceFile("a.py", "secret_code = 1\n")]

    def make(owner="alice", key=None, fingerprint="fp1", **kw):
        return store.create(owner, fingerprint, key, files, None, None, kw.get("client_ref"), None)

    # create, find, and the resource shape
    job, replayed = make(client_ref="wi-7")
    assert replayed is False and job.id.startswith("scn_") and job.status == "queued" and len(store) == 1
    assert store.get(job.id, "alice") is job
    assert job.to_resource() == {"id": job.id, "status": "queued", "created_at": "1970-01-01T02:46:40Z", "completed_at": None, "client_ref": "wi-7", "report": None}

    # OWNERSHIP: another caller cannot see, find or delete it, and cannot tell it exists
    assert store.get(job.id, "mallory") is None and store.delete(job.id, "mallory") is False and store.get(job.id, "alice") is job

    # the job's life: running, then completed with a report; a job that finished says so
    assert store.mark_running(job) and job.status == "running"
    store.complete(job, {"decision": "pass"})
    assert job.status == "completed" and job.done.is_set() and job.completed_at == now[0]
    assert job.to_resource()["report"] == {"decision": "pass"} and job.to_resource()["completed_at"] == "1970-01-01T02:46:40Z"
    crashed, _ = make()
    store.fail(crashed)
    assert crashed.status == "failed" and crashed.to_resource()["report"] is None and crashed.done.is_set()
    store.delete(crashed.id, "alice")

    # IDEMPOTENCY: same caller, same key, same request -> the original job; a different request -> a conflict
    first, replayed = make(key="K1")
    again, replayed_again = make(key="K1")
    assert replayed is False and replayed_again is True and again is first and len(store) == 2
    try:
        make(key="K1", fingerprint="other-request")
        raise AssertionError("expected a conflict")
    except IdempotencyConflict:
        pass
    other_owner, replayed_other = make(owner="bob", key="K1")                 # keys are scoped per caller
    assert replayed_other is False and other_owner is not first and len(store) == 3
    no_key_1, _ = store.create("alice", "fp1", None, files, None, None, None, None) if len(store) < 3 else (None, None)

    # BOUNDS: a full store refuses new jobs instead of growing; replays of existing keys still work
    try:
        make(owner="carol")
        raise AssertionError("expected the store to be full")
    except StoreFull:
        pass
    assert make(key="K1")[1] is True

    # DELETE: the code and the result go at once, the idempotency key is freed, and a second delete finds nothing
    assert store.delete(first.id, "alice") is True and first.files is None and first.report is None and first.deleted
    assert store.get(first.id, "alice") is None and store.delete(first.id, "alice") is False
    fresh, replayed_fresh = make(key="K1")
    assert replayed_fresh is False and fresh is not first                      # the key is free again after deletion

    # a scan that finishes AFTER it was deleted is thrown away, and cannot bring the job back
    late = fresh
    store.delete(late.id, "alice")
    store.mark_running(late)
    store.complete(late, {"decision": "block"})
    assert late.report is None and late.status != "completed" and store.get(late.id, "alice") is None

    # RETENTION: after the window the job, its code and its key are gone (and the sweep says how many)
    keep, _ = make(key="K2")
    now[0] += 3599
    assert store.get(keep.id, "alice") is keep
    now[0] += 2
    assert store.get(keep.id, "alice") is None and keep.files is None
    assert store.purge_expired() == 0 and len(store) == 0
    old, _ = make()
    other_old, _ = make(owner="bob")
    now[0] += 4000
    assert store.purge_expired() == 2 and old.deleted and other_old.deleted and len(store) == 0
    assert make(key="K2")[1] is False                                          # an expired key can be used again

    # waiting on a job is released when it ends any way
    waiting, _ = make(owner="dave")
    assert not waiting.done.is_set()
    store.delete(waiting.id, "dave")
    assert waiting.done.is_set()

    try:
        JobStore(0)
        raise AssertionError("a retention of zero must be refused")
    except ValueError:
        pass
    print("api.jobs OK: ownership hides other callers' jobs, idempotency per caller, retention and delete remove the code, a late result cannot resurrect a deleted job")


if __name__ == "__main__":
    demo()
