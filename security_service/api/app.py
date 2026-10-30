"""
security_service/api/app.py

The web layer: HTTP in, gateway call, HTTP out. All rules live in gateway.py; this file only translates, so it stays small.

What it adds on top of the gateway:
  - one route per operation of the contract (openapi.yaml), and nothing else: no auto-generated docs or schema, because the
    contract file is the single source of truth and a second description could drift from it;
  - EVERY error is a contract `Problem` (application/problem+json) carrying a request id: unknown paths, wrong methods,
    bad JSON and unexpected crashes included. An unexpected crash says only "internal error": no message, no trace;
  - the body is read with a size limit WHILE it is read, and only after the key has been checked, so an unauthenticated
    caller's body is never read at all and nobody can fill memory with an endless upload;
  - headers on every response: X-Request-ID, Cache-Control: no-store (results quote code), X-Content-Type-Options: nosniff;
  - one log line per request: method, path, status, time, caller name and request id. Never a body, a key or a header value.

The service speaks plain HTTP. Put HTTPS in front of it (a reverse proxy or the platform's ingress) before it is reachable
from anywhere but this computer.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from security_service.api.auth import Principal, parse_api_keys
from security_service.api.gateway import ApiError, Gateway, Reply
from security_service.api.jobs import JobStore
from security_service.api.ratelimit import RateLimiter
from security_service.core.errors import api_problem
from security_service.core.scan_service import ScanService

log = logging.getLogger("security_service.api")


DRAIN_LIMIT = 8_000_000     # how much of an oversized upload is read and thrown away so the caller can read the 413 answer


async def _drain(request: Request, already: int = 0) -> None:
    """Read and discard the rest of an oversized upload, holding none of it, so the caller finishes sending and sees a clear 413
    instead of a dropped connection. Past DRAIN_LIMIT the connection is simply left to close."""
    total = already
    async for chunk in request.stream():
        total += len(chunk)
        if total > DRAIN_LIMIT:
            return


async def read_limited(request: Request, limit: int) -> bytes:
    """The request body, refusing to HOLD more than `limit` bytes however it is sent (with or without a Content-Length)."""
    too_big = ApiError("payload_too_large", f"The request body is larger than this service accepts ({limit} bytes).")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        await _drain(request)
        raise too_big
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            await _drain(request, size)
            raise too_big
        chunks.append(chunk)
    return b"".join(chunks)


def _answer(reply: Reply, request: Request) -> Response:
    if reply.status == 204:
        response: Response = Response(status_code=204)
    else:
        body = reply.body
        is_problem = reply.status >= 400 and isinstance(body, dict) and "code" in body
        if is_problem and "request_id" not in body:
            body = {**body, "request_id": request.state.request_id}
        response = JSONResponse(body, status_code=reply.status, media_type="application/problem+json" if is_problem else "application/json")
    for name, value in reply.headers.items():
        response.headers[name] = value
    return response


def create_app(gateway: Gateway) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        gateway.start_sweeper()
        try:
            yield
        finally:
            gateway.shutdown()

    app = FastAPI(title="Flwn security service", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def frame(request: Request, call_next):
        request.state.request_id = f"req_{uuid.uuid4().hex[:16]}"
        request.state.principal = None
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as problem:                                    # noqa: BLE001 - the last line of defense
            log.error("unhandled %s on %s %s (%s)", type(problem).__name__, request.method, request.url.path, request.state.request_id)
            response = _answer(ApiError("internal_error", "The service hit an unexpected error. Nothing about your request is shown here.").reply(), request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        log.info("%s %s -> %d in %d ms (caller=%s, %s)", request.method, request.url.path, response.status_code,
                 (time.monotonic() - started) * 1000, request.state.principal or "-", request.state.request_id)
        return response

    def authed(request: Request, scope: str | None) -> Principal:
        principal = gateway.authorize(request.headers.get("authorization"), scope)
        request.state.principal = principal.name
        return principal

    async def guarded(request: Request, work) -> Response:
        try:
            reply = await work()
        except ApiError as problem:
            reply = problem.reply(request.state.request_id)
        return _answer(reply, request)

    # ------------------------------------------------------------------ the operations of the contract

    @app.post("/v1/scans")
    async def create_scan(request: Request):
        async def work():
            principal = authed(request, "scan")
            body = await read_limited(request, gateway.max_body_bytes)
            headers = {name.lower(): value for name, value in request.headers.items()}
            return await run_in_threadpool(gateway.create_scan, principal, headers, body)
        return await guarded(request, work)

    @app.get("/v1/scans/{scan_id}")
    async def get_scan(scan_id: str, request: Request):
        async def work():
            return gateway.get_scan(authed(request, "read"), scan_id)
        return await guarded(request, work)

    @app.delete("/v1/scans/{scan_id}")
    async def delete_scan(scan_id: str, request: Request):
        async def work():
            return gateway.delete_scan(authed(request, "scan"), scan_id)
        return await guarded(request, work)

    @app.post("/v1/scans/{scan_id}/fixes")
    async def create_fix(scan_id: str, request: Request):
        async def work():
            authed(request, "fix")
            return gateway.not_available("Fixes")
        return await guarded(request, work)

    @app.get("/v1/fixes/{fix_id}")
    async def get_fix(fix_id: str, request: Request):
        async def work():
            authed(request, "read")
            return gateway.unknown("fix")
        return await guarded(request, work)

    @app.post("/v1/verifications")
    async def create_verification(request: Request):
        async def work():
            authed(request, "scan")
            return gateway.not_available("Verifications")
        return await guarded(request, work)

    @app.get("/v1/verifications/{verification_id}")
    async def get_verification(verification_id: str, request: Request):
        async def work():
            authed(request, "read")
            return gateway.unknown("verification")
        return await guarded(request, work)

    @app.get("/v1/capabilities")
    async def capabilities(request: Request):
        async def work():
            authed(request, None)
            return gateway.capabilities()
        return await guarded(request, work)

    @app.get("/healthz")
    async def healthz(request: Request):
        return _answer(gateway.health(), request)

    @app.get("/readyz")
    async def readyz(request: Request):
        return _answer(await run_in_threadpool(gateway.ready), request)

    # ------------------------------------------------------------------ every other kind of failure is a Problem too

    @app.exception_handler(StarletteHTTPException)
    async def http_problem(request: Request, error: StarletteHTTPException):
        if error.status_code == 404:
            reply = ApiError("not_found", "No such path.").reply(request.state.request_id)
        elif error.status_code == 405:
            reply = Reply(405, {**api_problem("invalid_request", "That method is not allowed on this path.", request.state.request_id),
                                "title": "Method not allowed", "status": 405}, dict(error.headers or {}))
        else:
            reply = ApiError("invalid_request", "The request could not be processed.").reply(request.state.request_id)
        return _answer(reply, request)

    @app.exception_handler(RequestValidationError)
    async def validation_problem(request: Request, _error: RequestValidationError):
        return _answer(ApiError("invalid_request", "The request could not be processed.").reply(request.state.request_id), request)

    return app


def build_app(settings, classifier=None) -> FastAPI:
    """The service as configured by environment settings. Raises ValueError, with a plain message, if it cannot start."""
    problems = settings.service_problems()
    if problems:
        raise ValueError("; ".join(problems))
    keyring, _ = parse_api_keys(settings.service_api_keys)
    service = ScanService.from_settings(settings, classifier=classifier)
    gateway = Gateway(service, keyring, JobStore(settings.service_retention_hours * 3600), RateLimiter(settings.service_rate_limit_per_minute),
                      workers=settings.service_workers, max_wait_seconds=settings.service_max_wait_seconds,
                      retention_hours=settings.service_retention_hours)
    return create_app(gateway)
