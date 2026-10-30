"""
security_service/core/errors.py

Maps the core's exceptions to the contract's error format (a Problem, shaped after RFC 9457).
Clients branch on `code`, which is stable; `title` and `detail` are for people.

Only messages the service itself wrote are passed through as `detail` (they describe the request,
for example "too many files"). Anything unexpected becomes a generic internal_error: stack traces,
provider messages and secrets must never reach a response body.
"""

from __future__ import annotations

from typing import Any

from security_service.core.files import InvalidScanInput, PayloadTooLarge, UnsupportedLanguage

# Order matters: subclasses first.
_MAP = (
    (PayloadTooLarge, 413, "payload_too_large", "Payload too large"),
    (UnsupportedLanguage, 422, "unsupported_language", "Unsupported language"),
    (InvalidScanInput, 400, "invalid_request", "Invalid request"),
)


def problem_for(exc: Exception, request_id: str | None = None) -> dict[str, Any]:
    for exc_type, status, code, title in _MAP:
        if isinstance(exc, exc_type):
            problem = {"type": "about:blank", "title": title, "status": status, "detail": str(exc), "code": code}
            break
    else:
        problem = {
            "type": "about:blank",
            "title": "Internal error",
            "status": 500,
            "detail": "The service could not complete the request.",
            "code": "internal_error",
        }
    if request_id:
        problem["request_id"] = request_id
    return problem


_API_PROBLEMS = {
    "invalid_request": (400, "Invalid request"),
    "unauthorized": (401, "Unauthorized"),
    "forbidden": (403, "Forbidden"),
    "not_found": (404, "Not found"),
    "idempotency_conflict": (409, "Idempotency conflict"),
    "payload_too_large": (413, "Payload too large"),
    "unsupported_language": (422, "Unsupported language"),
    "rate_limited": (429, "Too many requests"),
    "internal_error": (500, "Internal error"),
    "not_implemented": (501, "Not implemented"),
    "provider_unavailable": (503, "Service unavailable"),
}


def api_problem(code: str, detail: str, request_id: str | None = None) -> dict[str, Any]:
    """A contract-shaped error body for the errors the HTTP layer itself raises. `code` is one of the contract's codes."""
    status, title = _API_PROBLEMS[code]
    problem: dict[str, Any] = {"type": "about:blank", "title": title, "status": status, "detail": detail, "code": code}
    if request_id:
        problem["request_id"] = request_id
    return problem


def demo() -> None:
    assert api_problem("unauthorized", "x") == {"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": "x", "code": "unauthorized"}
    assert api_problem("not_implemented", "y", "req_1")["status"] == 501 and api_problem("not_implemented", "y", "req_1")["request_id"] == "req_1"
    assert {code for code in _API_PROBLEMS} | {"payload_too_large", "unsupported_language", "invalid_request"} == set(_API_PROBLEMS)
    try:
        api_problem("telepathy", "z")
        raise AssertionError("an unknown code must be refused")
    except KeyError:
        pass
    assert problem_for(PayloadTooLarge("too many files (51, limit 50)"))["status"] == 413
    assert problem_for(UnsupportedLanguage("x"))["code"] == "unsupported_language"
    assert problem_for(InvalidScanInput("at least one file is required"))["code"] == "invalid_request"
    secret = problem_for(RuntimeError("provider said: key sk-live-EXAMPLE0000000000000000 is invalid"), "req_9")
    assert secret["status"] == 500 and secret["code"] == "internal_error" and secret["request_id"] == "req_9"
    assert "sk-live" not in str(secret) and "provider" not in str(secret)
    print("core.errors OK: contract error codes, nothing internal leaks into a response")


if __name__ == "__main__":
    demo()
