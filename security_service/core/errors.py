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


def demo() -> None:
    assert problem_for(PayloadTooLarge("too many files (51, limit 50)"))["status"] == 413
    assert problem_for(UnsupportedLanguage("x"))["code"] == "unsupported_language"
    assert problem_for(InvalidScanInput("at least one file is required"))["code"] == "invalid_request"
    secret = problem_for(RuntimeError("provider said: key sk-live-EXAMPLE0000000000000000 is invalid"), "req_9")
    assert secret["status"] == 500 and secret["code"] == "internal_error" and secret["request_id"] == "req_9"
    assert "sk-live" not in str(secret) and "provider" not in str(secret)
    print("core.errors OK: contract error codes, nothing internal leaks into a response")


if __name__ == "__main__":
    demo()
