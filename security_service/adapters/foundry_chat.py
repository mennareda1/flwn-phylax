"""
security_service/adapters/foundry_chat.py

One chat request to a GPT-6 Astra deployment on Microsoft Foundry, with the retries, timeouts and error handling the other
adapters have. It knows HTTP and the reply format; it knows nothing about fixing code (that is foundry_corrector.py).

What it sends (what GPT-6 Astra accepts, from OpenAI's and Microsoft's model pages and from people who probed the live API):
    model                  the DEPLOYMENT name, not the model's display name
    messages               a system message and a user message; no tools (tool calling needs the Responses API, and a
                           corrector does not need tools)
    max_completion_tokens  NOT max_tokens: reasoning models refuse the old name. It caps the thinking plus the answer.
    reasoning_effort       low, medium, high or xhigh. "none" and "minimal" are refused by Astra.
It never sends temperature, top_p or logprobs, which Astra refuses.

Why a cap matters here: Astra's thinking is billed as OUTPUT, at 50 US dollars per million tokens, and it counts against
max_completion_tokens. Too small a cap leaves nothing for the answer (finish_reason "length" and empty text); the caller
treats that as a failure with its own message. The defaults are low effort and 8000 tokens.

Two routes exist on a Foundry resource, and which one answers depends on how it is set up, so it is a setting
(CORRECTOR_API) and tests/live_corrector.py tests both:
    openai_v1   POST <resource>/openai/v1/chat/completions
    inference   POST <resource>/models/chat/completions?api-version=2024-05-01-preview   (the route Flwn's own SDK uses;
                extra parameters need the header  extra-parameters: pass-through )

Errors never carry the submitted code, the key, or the provider's free text: a status, the provider's short error code and the
name of the parameter it objected to ("param"), plus a hint.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from security_service.adapters.decision1 import Transport, _TransportFailure, _urllib_transport
from security_service.config import Settings, normalize_endpoint
from security_service.ports.corrector import CorrectorRejected, CorrectorUnavailable

RETRY_STATUSES = {408, 409, 425, 429, 500, 502, 503, 504}
MAX_RETRY_WAIT_SECONDS = 20.0
INFERENCE_API_VERSION = "2024-05-01-preview"
ROUTES = ("openai_v1", "inference")


@dataclass(frozen=True)
class ChatReply:
    text: str
    finish_reason: str
    model: str                 # the exact model id the provider says answered
    prompt_tokens: int
    completion_tokens: int     # includes the thinking
    reasoning_tokens: int      # the part of completion_tokens that was thinking (0 if the provider does not say)
    seconds: float
    route: str


class FoundryChat:
    def __init__(self, deployment: str, endpoint: str, api_key: str, *, route: str = "openai_v1", reasoning_effort: str = "low",
                 max_output_tokens: int = 8000, timeout: float = 180.0, max_attempts: int = 3,
                 transport: Transport | None = None, sleep: Callable[[float], None] = time.sleep):
        if route not in ROUTES:
            raise ValueError(f"route must be one of {ROUTES}")
        if not deployment.strip() or not endpoint.strip() or not api_key.strip():
            raise ValueError("deployment, endpoint and api_key are all required")
        self.deployment, self.route = deployment, route
        self._host = normalize_endpoint(endpoint)
        self._key = api_key
        self._effort, self._max_tokens, self._timeout, self._attempts = reasoning_effort, max_output_tokens, timeout, max_attempts
        self._transport: Transport = transport or _urllib_transport
        self._sleep = sleep

    @classmethod
    def from_settings(cls, settings: Settings, **overrides: Any) -> "FoundryChat":
        problems = settings.corrector_problems()
        if problems:
            raise ValueError("the corrector is not ready: " + "; ".join(problems))
        return cls(settings.corrector_deployment, settings.corrector_resolved_endpoint, settings.corrector_resolved_key,
                   route=settings.corrector_api, reasoning_effort=settings.corrector_reasoning_effort,
                   max_output_tokens=settings.corrector_max_output_tokens, timeout=settings.corrector_timeout, **overrides)

    # ------------------------------------------------------------------ request

    @property
    def url(self) -> str:
        if self.route == "openai_v1":
            return f"{self._host}/openai/v1/chat/completions"
        return f"{self._host}/models/chat/completions?api-version={INFERENCE_API_VERSION}"

    def build_request(self, system: str, user: str) -> bytes:
        return json.dumps({
            "model": self.deployment,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_completion_tokens": self._max_tokens,
            "reasoning_effort": self._effort,
        }).encode("utf-8")

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json", "api-key": self._key}
        if self.route == "inference":
            headers["extra-parameters"] = "pass-through"          # lets the inference route forward max_completion_tokens and reasoning_effort
        return headers

    # ------------------------------------------------------------------ the call

    def chat(self, system: str, user: str) -> ChatReply:
        payload = self.build_request(system, user)
        started = time.monotonic()
        last, last_status = "no attempt made", None
        for attempt in range(1, self._attempts + 1):
            reply_headers: dict = {}
            try:
                status, reply_headers, raw = self._transport(self.url, self._headers(), payload, self._timeout)
            except _TransportFailure as failure:
                last = f"network error ({failure})"
            else:
                if status < 400:
                    return self._parse(raw, time.monotonic() - started)
                if status not in RETRY_STATUSES:
                    raise self._rejected(status, raw)
                last, last_status = f"HTTP {status}", status
            if attempt < self._attempts:
                self._sleep(self._delay(attempt, reply_headers))
        hint = "; the deployment's rate limit was exceeded: add capacity or lower the request rate" if last_status == 429 else ""
        raise CorrectorUnavailable(f"{self.deployment} unavailable after {self._attempts} attempts (last: {last}){hint}")

    @staticmethod
    def _delay(attempt: int, headers: dict) -> float:
        retry_after = str(headers.get("retry-after", "")).strip()
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_WAIT_SECONDS)
        return 0.5 * 2 ** (attempt - 1)

    _HINTS = {
        400: "the provider refused a request parameter; check CORRECTOR_REASONING_EFFORT (Astra accepts low, medium, high, xhigh) and CORRECTOR_MAX_OUTPUT_TOKENS",
        401: "the key is missing, wrong or expired",
        403: "this key has no access to the deployment",
        404: "the route or the deployment name is wrong: check CORRECTOR_DEPLOYMENT (the Name column in Foundry), and try the other CORRECTOR_API route",
        422: "the provider could not accept the request body for this route; try the other CORRECTOR_API route",
    }

    @classmethod
    def _rejected(cls, status: int, raw: bytes) -> CorrectorRejected:
        hint = cls._HINTS.get(status)
        suffix = f": {hint}" if hint else ""
        if status in (401, 403):
            return CorrectorRejected(f"authentication failed (HTTP {status}){suffix}", status=status)
        detail = ""
        try:
            error = json.loads(raw).get("error")
            if isinstance(error, dict):
                for field in ("code", "param"):
                    value = error.get(field)
                    if isinstance(value, str) and 0 < len(value) <= 60 and all(c.isalnum() or c in "_.-" for c in value):
                        detail += f", {field} {value}"
        except (ValueError, AttributeError):
            pass
        return CorrectorRejected(f"request rejected by the provider (HTTP {status}{detail}){suffix}", status=status)

    def _parse(self, raw: bytes, seconds: float) -> ChatReply:
        try:
            data = json.loads(raw)
            choice = data["choices"][0]
            text = (choice.get("message") or {}).get("content") or ""
            usage = data.get("usage") or {}
            details = usage.get("completion_tokens_details") or {}
            return ChatReply(text=text if isinstance(text, str) else "", finish_reason=str(choice.get("finish_reason") or ""),
                             model=str(data.get("model") or self.deployment), prompt_tokens=int(usage.get("prompt_tokens") or 0),
                             completion_tokens=int(usage.get("completion_tokens") or 0), reasoning_tokens=int(details.get("reasoning_tokens") or 0),
                             seconds=seconds, route=self.route)
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise CorrectorUnavailable("the provider's reply is not a readable chat completion (no choices); the route may be wrong") from None


def demo() -> None:
    import threading

    secret_key = "real-looking-key-0123456789"
    ok = json.dumps({"model": "gpt-6-astra-2026-09-03", "choices": [{"message": {"content": '{"edits": []}'}, "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": 410, "completion_tokens": 1900, "completion_tokens_details": {"reasoning_tokens": 1700}}}).encode()

    class Script:
        def __init__(self, steps):
            self.steps, self.calls = list(steps), []

        def __call__(self, url, headers, body, timeout):
            self.calls.append((url, headers, json.loads(body), timeout))
            step = self.steps[min(len(self.calls) - 1, len(self.steps) - 1)]
            if isinstance(step, Exception):
                raise step
            return step

    def make(steps, **kw):
        script = Script(steps)
        slept: list[float] = []
        return FoundryChat("gpt-6-astra", "https://res.services.ai.azure.com/providers/microsoft/v1/systemone", secret_key, transport=script,
                           sleep=slept.append, **kw), script, slept

    def refused(chat, exc_type, **bits):
        try:
            chat.chat("SYSTEM-TEXT", "USER-CODE-SECRET")
            raise AssertionError(f"expected {exc_type.__name__}")
        except exc_type as problem:
            text = str(problem)
            assert secret_key not in text and "USER-CODE-SECRET" not in text and "SYSTEM-TEXT" not in text, "an error message leaked"
            for needle in bits.get("has", ()):
                assert needle in text, (needle, text)
            return problem

    # request shape, route 1: the resource host is reduced from a pasted Decision-1 URL; Astra's parameters, and none it refuses
    chat, script, _ = make([(200, {}, ok)])
    reply = chat.chat("SYSTEM-TEXT", "USER-CODE-SECRET")
    url, headers, body, timeout = script.calls[0]
    assert url == "https://res.services.ai.azure.com/openai/v1/chat/completions" and headers["api-key"] == secret_key and "extra-parameters" not in headers
    assert body == {"model": "gpt-6-astra", "messages": [{"role": "system", "content": "SYSTEM-TEXT"}, {"role": "user", "content": "USER-CODE-SECRET"}],
                    "max_completion_tokens": 8000, "reasoning_effort": "low"}
    assert not {"temperature", "top_p", "logprobs", "max_tokens", "tools", "tool_choice"} & set(body) and timeout == 180.0
    assert (reply.text, reply.finish_reason, reply.model, reply.prompt_tokens, reply.completion_tokens, reply.reasoning_tokens, reply.route) == \
        ('{"edits": []}', "stop", "gpt-6-astra-2026-09-03", 410, 1900, 1700, "openai_v1")

    # route 2 uses the inference path and asks the service to pass the extra parameters through
    chat2, script2, _ = make([(200, {}, ok)], route="inference", reasoning_effort="high", max_output_tokens=3000)
    chat2.chat("s", "u")
    url2, headers2, body2, _ = script2.calls[0]
    assert url2 == "https://res.services.ai.azure.com/models/chat/completions?api-version=2024-05-01-preview" and headers2["extra-parameters"] == "pass-through"
    assert body2["reasoning_effort"] == "high" and body2["max_completion_tokens"] == 3000

    # a reply without usage details still parses; an empty or missing content gives empty text (the caller decides what that means)
    bare = json.dumps({"choices": [{"message": {"content": None}, "finish_reason": "length"}]}).encode()
    thin = make([(200, {}, bare)])[0].chat("s", "u")
    assert thin.text == "" and thin.finish_reason == "length" and thin.completion_tokens == 0 and thin.reasoning_tokens == 0 and thin.model == "gpt-6-astra"

    # retries: rate limits and server errors are retried (honoring Retry-After), then it gives up with a clear, content-free message
    chat, script, slept = make([(429, {"retry-after": "2"}, b"{}"), (503, {}, b"{}"), (200, {}, ok)])
    assert chat.chat("s", "u").text == '{"edits": []}' and len(script.calls) == 3 and slept == [2.0, 1.0]
    chat, script, _ = make([(429, {}, b"{}")])
    problem = refused(chat, CorrectorUnavailable, has=["unavailable after 3 attempts", "HTTP 429", "rate limit"])
    chat, _, _ = make([_TransportFailure("TimeoutError"), _TransportFailure("TimeoutError"), _TransportFailure("TimeoutError")])
    refused(chat, CorrectorUnavailable, has=["network error (TimeoutError)"])

    # refusals are not retried, and say which parameter the provider objected to without repeating anything we sent
    for status, bits in ((400, ["HTTP 400", "code unsupported_parameter", "param max_tokens", "CORRECTOR_REASONING_EFFORT"]),
                         (404, ["HTTP 404", "CORRECTOR_DEPLOYMENT", "the other CORRECTOR_API route"]),
                         (401, ["authentication failed (HTTP 401)"]), (403, ["HTTP 403", "no access"])):
        body_bytes = json.dumps({"error": {"code": "unsupported_parameter", "param": "max_tokens", "message": "USER-CODE-SECRET leaked here"}}).encode()
        chat, script, _ = make([(status, {}, body_bytes)])
        problem = refused(chat, CorrectorRejected, has=bits)
        assert len(script.calls) == 1 and problem.status == status
    chat, _, _ = make([(400, {}, json.dumps({"error": {"code": "x" * 200, "param": "has space"}}).encode())])
    assert ", code" not in str(refused(chat, CorrectorRejected)) and ", param" not in str(refused(chat, CorrectorRejected))   # odd values are not echoed
    chat, _, _ = make([(400, {}, b"<html>not json</html>")])
    refused(chat, CorrectorRejected, has=["HTTP 400"])

    # a 200 that is not a chat completion is an unavailable provider, not a crash
    for junk in (b"not json", b"{}", b'{"choices": []}', b'{"choices": [1]}'):
        refused(make([(200, {}, junk)])[0], CorrectorUnavailable, has=["not a readable chat completion"])

    # construction: configuration is checked, and settings give a ready client
    for bad in (("", "https://x", "k"), ("d", "", "k"), ("d", "https://x", " ")):
        try:
            FoundryChat(*bad)
            raise AssertionError("missing configuration must be refused")
        except ValueError:
            pass
    try:
        FoundryChat("d", "https://x", "k", route="soap")
        raise AssertionError("an unknown route must be refused")
    except ValueError:
        pass
    ready = FoundryChat.from_settings(Settings.from_env({"FOUNDRY_ENDPOINT": "https://res.services.ai.azure.com", "FOUNDRY_API_KEY": "real-looking-key-1", "CORRECTOR_DEPLOYMENT": "gpt-6-astra",
                                                         "CORRECTOR_API": "inference", "CORRECTOR_REASONING_EFFORT": "medium", "CORRECTOR_MAX_OUTPUT_TOKENS": "5000"}))
    assert ready.route == "inference" and ready._effort == "medium" and ready._max_tokens == 5000
    try:
        FoundryChat.from_settings(Settings.from_env({"FOUNDRY_ENDPOINT": "https://res.services.ai.azure.com", "FOUNDRY_API_KEY": "real-looking-key-1"}))
        raise AssertionError("no deployment must be refused")
    except ValueError as problem:
        assert "No deployment" in str(problem)

    # the real transport against a real local server: a 200, and a 4xx with a body
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            wrong = self.headers.get("api-key") != secret_key
            payload = ok if not wrong else json.dumps({"error": {"code": "Unauthorized"}}).encode()
            self.send_response(401 if wrong else 200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        host = f"http://127.0.0.1:{server.server_address[1]}"
        assert FoundryChat("gpt-6-astra", host, secret_key).chat("s", "u").completion_tokens == 1900
        refused(FoundryChat("gpt-6-astra", host, "wrong-key-wrong-key"), CorrectorRejected, has=["authentication failed"])
    finally:
        server.shutdown()

    print("adapters.foundry_chat OK: Astra's parameters (and none it refuses), both routes, retries with Retry-After, refusals that name the parameter, no key or content in any error")


if __name__ == "__main__":
    demo()
