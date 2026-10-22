"""
security_service/adapters/decision1.py

Classifier adapter for Microsoft-Decision-1 on Microsoft Foundry.

What it does: sends one piece of code (the "state") plus named yes/no or pick-one questions to
    POST <foundry-resource-endpoint>/providers/microsoft/v1/systemone
and returns typed answers with probabilities, in the shape the classifier port defines.

Configuration (constructor arguments win; from_env() reads the environment):
    FOUNDRY_ENDPOINT      the resource host, e.g. https://<resource>.services.ai.azure.com
    FOUNDRY_API_KEY       sent as the `api-key` header; or pass token_provider to use a Microsoft
                          Entra ID token as a Bearer token instead (scope
                          https://cognitiveservices.azure.com/.default)
    DECISION1_DEPLOYMENT  the deployment name you chose in Foundry (default "decision-1"); it is what
                          the request's `model` field carries
    DECISION1_MODEL_VERSION  the model version chosen at deployment (default "1"); reported in every
                          result as "Microsoft-Decision-1@<version>", never an alias

Behavior worth knowing:
  - Secrets are masked inside this adapter before anything is sent (core/redaction.py), as the last
    line of defense at the boundary where code leaves the system. Masking is idempotent.
  - Only transient failures are retried (HTTP 408, 429, 500, 502, 503, 504 and network errors), up
    to 3 attempts, honoring Retry-After (capped at 10 s). Anything else fails at once.
  - Errors never contain the submitted code or any credential.
  - No new dependency: it uses urllib. The network call is injectable, so tests need no network.

NOT YET RUN AGAINST A REAL DEPLOYMENT. The request shape follows what Microsoft documents (a model,
a state, questions keyed by name, each noul / choice / score with instructions and criteria). The
reply parsing follows the "System One" format described by third parties (noul: a probability;
choice: the choice, a probability per option, a confidence). Parsing is deliberately tolerant about
field names, but the first real reply must be checked: run `python -m tests.live_decision1`.
"""

from __future__ import annotations

import json
import math
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from security_service.core.redaction import redact_secrets
from security_service.ports.classifier import (
    Answer,
    ClassifierError,
    ClassifierRejected,
    ClassifierResult,
    ClassifierUnavailable,
    Question,
    StateTooLarge,
    validate_questions,
    validate_result,
)

MODEL_NAME = "Microsoft-Decision-1"
SYSTEMONE_PATH = "/providers/microsoft/v1/systemone"
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRY_WAIT_SECONDS = 10.0
_ENDPOINT_SUFFIXES = ("/openai/v1", "/openai", "/models")

Transport = Callable[[str, dict, bytes, float], "tuple[int, dict, bytes]"]


class _TransportFailure(Exception):
    """A network-level failure (no HTTP response). Carries only the error's class name."""


def _urllib_transport(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise _TransportFailure(type(error).__name__) from None


def normalize_endpoint(endpoint: str) -> str:
    """The resource host, without a trailing slash or an API suffix someone pasted from another setting."""
    cleaned = endpoint.strip().rstrip("/")
    for suffix in _ENDPOINT_SUFFIXES:
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)].rstrip("/")
    return cleaned


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


class Decision1Classifier:
    role = "classifier"
    name = "microsoft-decision-1"
    # Microsoft's page gives about 32K tokens of input; keep headroom for the questions themselves.
    max_state_tokens = 30_000

    def __init__(
        self,
        deployment: str = "decision-1",
        model_version: str = "1",
        endpoint: str | None = None,
        api_key: str | None = None,
        token_provider: Callable[[], str] | None = None,
        timeout: float = 20.0,
        max_attempts: int = 3,
        redact: bool = True,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._deployment = deployment
        self._model_version = model_version
        self._endpoint = normalize_endpoint(endpoint if endpoint is not None else os.getenv("FOUNDRY_ENDPOINT", ""))
        self._api_key = api_key if api_key is not None else os.getenv("FOUNDRY_API_KEY", "")
        self._token_provider = token_provider
        self._timeout = timeout
        self._max_attempts = max(1, max_attempts)
        self._redact = redact
        self._transport: Transport = transport or _urllib_transport
        self._sleep = sleep
        self.last_raw: dict | None = None   # the last parsed reply (answers and usage only); for debugging and the live test

    @classmethod
    def from_env(cls, **overrides: Any) -> "Decision1Classifier":
        return cls(
            deployment=os.getenv("DECISION1_DEPLOYMENT", "decision-1"),
            model_version=os.getenv("DECISION1_MODEL_VERSION", "1"),
            **overrides,
        )

    # ------------------------------------------------------------------ public

    def classify(self, state: str, questions: list[Question]) -> ClassifierResult:
        payload = self.build_request(state, questions)
        return self._parse(self._post(payload), questions)

    def build_request(self, state: str, questions: list[Question]) -> bytes:
        """The exact bytes that will be sent: validated, masked and size-checked. Raises before any network call."""
        validate_questions(questions)
        if not self._endpoint or not (self._api_key or self._token_provider):
            raise ClassifierError("FOUNDRY_ENDPOINT and either FOUNDRY_API_KEY or a token provider are required")

        text = redact_secrets(state)[0] if self._redact else state
        if math.ceil(len(text) / 3) > self.max_state_tokens:   # rough and cautious: about 3 characters per token
            raise StateTooLarge(f"code is too large for one question (limit about {self.max_state_tokens} tokens); chunk it first")

        body = {
            "model": self._deployment,
            "state": text,
            "questions": {q.id: self._question_body(q) for q in questions},
        }
        return json.dumps(body).encode("utf-8")

    def send(self, payload: bytes) -> bytes:
        """Post a request built by build_request, with retries; returns the raw reply bytes."""
        return self._post(payload)

    # ------------------------------------------------------------------ request

    @staticmethod
    def _question_body(question: Question) -> dict:
        if question.kind == "yes_no":
            return {"type": "noul", "instructions": question.instructions}
        return {"type": "choice", "instructions": question.instructions, "criteria": dict(question.options or {})}

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token_provider is not None:
            headers["Authorization"] = f"Bearer {self._token_provider()}"
        else:
            headers["api-key"] = self._api_key
        return headers

    def _post(self, payload: bytes) -> bytes:
        url = self._endpoint + SYSTEMONE_PATH
        last = "no attempt made"
        for attempt in range(1, self._max_attempts + 1):
            reply_headers: dict = {}
            try:
                status, reply_headers, raw = self._transport(url, self._headers(), payload, self._timeout)
            except _TransportFailure as failure:
                last = f"network error ({failure})"
            else:
                if status < 400:
                    return raw
                if status not in RETRY_STATUSES:
                    raise self._rejected(status, raw)
                last = f"HTTP {status}"
            if attempt < self._max_attempts:
                self._sleep(self._delay(attempt, reply_headers))
        raise ClassifierUnavailable(f"{MODEL_NAME} unavailable after {self._max_attempts} attempts (last: {last})")

    @staticmethod
    def _delay(attempt: int, headers: dict) -> float:
        retry_after = str(headers.get("retry-after", "")).strip()
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_WAIT_SECONDS)
        return 0.5 * 2 ** (attempt - 1)

    @staticmethod
    def _rejected(status: int, raw: bytes) -> ClassifierRejected:
        if status in (401, 403):
            return ClassifierRejected(f"authentication failed (HTTP {status}): check the key, token or resource permissions")
        code = ""
        try:
            error = json.loads(raw).get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), str) and len(error["code"]) <= 60:
                code = f", code {error['code']}"
        except (ValueError, AttributeError):
            pass
        return ClassifierRejected(f"request rejected by the provider (HTTP {status}{code})")

    # ------------------------------------------------------------------ reply

    def _parse(self, raw: bytes, questions: list[Question]) -> ClassifierResult:
        try:
            data = json.loads(raw)
        except ValueError:
            raise ClassifierError("provider reply was not valid JSON") from None
        answers_raw = data.get("answers") if isinstance(data, dict) else None
        if not isinstance(answers_raw, dict):
            raise ClassifierError("provider reply has no 'answers' object")

        answers = {}
        for question in questions:
            if question.id not in answers_raw:
                raise ClassifierError(f"provider reply is missing the answer for question {question.id!r}")
            answers[question.id] = self._parse_answer(question, answers_raw[question.id])

        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        tokens = _number(usage.get("input_tokens", usage.get("prompt_tokens")))
        result = ClassifierResult(answers, f"{MODEL_NAME}@{self._model_version}", int(tokens or 0))
        try:
            validate_result(questions, result)
        except ValueError as problem:
            raise ClassifierError(f"provider reply failed validation: {problem}") from None
        self.last_raw = {"answers": answers_raw, "usage": usage}
        return result

    @staticmethod
    def _parse_answer(question: Question, item: Any) -> Answer:
        if question.kind == "yes_no":
            value = _number(item) if not isinstance(item, dict) else _number(item.get("noul", item.get("probability")))
            if value is None or not 0.0 <= value <= 1.0:
                raise ClassifierError(f"answer for {question.id!r} has no probability between 0 and 1")
            return Answer("yes_no", probability=value)

        if not isinstance(item, dict):
            raise ClassifierError(f"answer for {question.id!r} is not an object")
        probabilities = None
        if isinstance(item.get("probabilities"), dict):
            probabilities = {str(k): _number(v) for k, v in item["probabilities"].items()}
            if any(v is None or not 0.0 <= v <= 1.0 for v in probabilities.values()):
                raise ClassifierError(f"answer for {question.id!r} has an invalid probability")
        choice = item.get("choice")
        if choice is None and probabilities:
            choice = max(probabilities, key=probabilities.get)
        if not isinstance(choice, str) or choice not in (question.options or {}):
            raise ClassifierError(f"answer for {question.id!r} chose an option that was not offered")
        return Answer("choice", choice=choice, probabilities=probabilities, confidence=_number(item.get("confidence")))


# ---------------------------------------------------------------------- self-test

def demo() -> None:
    KEY = "test-key-0123456789"
    SECRET_STATE = 'DB_PASSWORD = "SuperSecret123!"\nimport os\nos.system("ping " + host)\n'
    URL = "https://res.services.ai.azure.com/providers/microsoft/v1/systemone"
    questions = [
        Question("secret", "yes_no", "Does the code contain a hardcoded password, key or token?"),
        Question("worst", "choice", "What is the most serious problem?",
                 {"hardcoded_secret": "a secret in the source", "command_injection": "shell built from input", "none": "nothing", "cannot_tell": "unclear"}),
    ]
    good = {"answers": {"secret": {"noul": 0.97},
                        "worst": {"choice": "command_injection", "confidence": 0.8,
                                  "probabilities": {"hardcoded_secret": 0.15, "command_injection": 0.8, "none": 0.02, "cannot_tell": 0.03}}},
            "usage": {"input_tokens": 61}}

    class Net:
        """Scripted network: a list of (status, headers, body) or an Exception to raise, consumed in order."""

        def __init__(self, script):
            self.script, self.calls = list(script), []

        def __call__(self, url, headers, body, timeout):
            self.calls.append({"url": url, "headers": headers, "body": body, "timeout": timeout})
            step = self.script.pop(0) if len(self.script) > 1 else self.script[0]
            if isinstance(step, Exception):
                raise step
            status, hdrs, payload = step
            return status, hdrs, payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def build(script, **kw):
        net = Net(script)
        sleeps: list[float] = []
        clf = Decision1Classifier(endpoint="https://res.services.ai.azure.com", api_key=KEY, transport=net, sleep=sleeps.append, **kw)
        return clf, net, sleeps

    def fails(exc_type, fn):
        try:
            fn()
        except exc_type as caught:
            text = str(caught)
            assert KEY not in text and "SuperSecret123" not in text and "ping" not in text, f"leak in error: {text}"
            return caught
        raise AssertionError(f"expected {exc_type.__name__}")

    # 1. success: request shape, headers, parsing, version-stamped model
    clf, net, _ = build([(200, {}, good)])
    result = clf.classify(SECRET_STATE, questions)
    call = net.calls[0]
    sent = json.loads(call["body"])
    assert call["url"] == URL and call["headers"]["api-key"] == KEY and "Authorization" not in call["headers"]
    assert sent["model"] == "decision-1" and sent["questions"]["secret"] == {"type": "noul", "instructions": questions[0].instructions}
    assert sent["questions"]["worst"]["type"] == "choice" and sent["questions"]["worst"]["criteria"]["none"] == "nothing"
    assert result.model == "Microsoft-Decision-1@1" and result.input_tokens == 61
    assert result.answers["secret"].probability == 0.97 and result.answers["worst"].choice == "command_injection"
    validate_result(questions, result)
    assert clf.last_raw["usage"] == {"input_tokens": 61}

    # 2. secrets are masked before anything is sent
    assert "SuperSecret123" not in call["body"].decode() and "<REDACTED_SECRET>" in sent["state"] and "os.system" in sent["state"]
    clf2, net2, _ = build([(200, {}, good)], redact=False)
    clf2.classify(SECRET_STATE, questions)
    assert "SuperSecret123" in net2.calls[0]["body"].decode()      # only because masking was switched off here

    # 3. Entra mode sends a Bearer token and no api-key
    net3 = Net([(200, {}, good)])
    Decision1Classifier(endpoint="https://res.services.ai.azure.com", token_provider=lambda: "tok123", transport=net3).classify("x = 1", questions)
    assert net3.calls[0]["headers"]["Authorization"] == "Bearer tok123" and "api-key" not in net3.calls[0]["headers"]

    # 4. endpoint normalization
    for raw in ("https://res.services.ai.azure.com/", "https://res.services.ai.azure.com/openai/v1", "https://res.services.ai.azure.com/models/"):
        assert normalize_endpoint(raw) == "https://res.services.ai.azure.com", raw

    # 5. transient failures are retried, Retry-After is honored, then success
    clf, net, sleeps = build([(429, {"retry-after": "2"}, b"{}"), (200, {}, good)])
    clf.classify("x = 1", questions)
    assert len(net.calls) == 2 and sleeps == [2.0]
    clf, net, sleeps = build([_TransportFailure("TimeoutError"), (503, {}, b""), (200, {}, good)])
    clf.classify("x = 1", questions)
    assert len(net.calls) == 3 and sleeps == [0.5, 1.0]
    clf, net, sleeps = build([(429, {"retry-after": "999"}, b"")] * 3)
    fails(ClassifierUnavailable, lambda: clf.classify(SECRET_STATE, questions))
    assert len(net.calls) == 3 and sleeps == [10.0, 10.0]          # capped; no sleep after the last attempt
    clf, net, sleeps = build([(500, {}, b"")] * 3)
    err = fails(ClassifierUnavailable, lambda: clf.classify(SECRET_STATE, questions))
    assert "3 attempts" in str(err) and "HTTP 500" in str(err)
    clf, net, sleeps = build([_TransportFailure("ConnectionResetError")] * 3)
    assert "network error" in str(fails(ClassifierUnavailable, lambda: clf.classify(SECRET_STATE, questions)))

    # 6. non-transient failures are not retried and say why, without leaking anything
    clf, net, _ = build([(401, {}, b'{"error": {"message": "bad key sk-live-EXAMPLE"}}')])
    err = fails(ClassifierRejected, lambda: clf.classify(SECRET_STATE, questions))
    assert len(net.calls) == 1 and "HTTP 401" in str(err) and "sk-live" not in str(err)
    clf, net, _ = build([(400, {}, b'{"error": {"code": "invalid_question", "message": "echo SuperSecret123"}}')])
    err = fails(ClassifierRejected, lambda: clf.classify(SECRET_STATE, questions))
    assert "HTTP 400" in str(err) and "invalid_question" in str(err)

    # 7. a reply that does not match the contract is an error, never a partial answer
    bad_replies = {
        "not json": b"<html>",
        "no answers": {"result": 1},
        "missing question": {"answers": {"secret": {"noul": 0.5}}},
        "probability above 1": {"answers": {**good["answers"], "secret": {"noul": 1.7}}},
        "boolean probability": {"answers": {**good["answers"], "secret": {"noul": True}}},
        "option not offered": {"answers": {**good["answers"], "worst": {"choice": "xss"}}},
        "choice reply is not an object": {"answers": {**good["answers"], "worst": "none"}},
        "bad option probability": {"answers": {**good["answers"], "worst": {"choice": "none", "probabilities": {"none": 3}}}},
    }
    for label, reply in bad_replies.items():
        clf, _, _ = build([(200, {}, reply)])
        fails(ClassifierError, lambda: clf.classify("x = 1", questions))

    # 8. tolerant where the format allows: a bare number, and a choice given only as probabilities
    lenient = {"answers": {"secret": 0.25, "worst": {"probabilities": {"hardcoded_secret": 0.1, "command_injection": 0.1, "none": 0.7, "cannot_tell": 0.1}}}}
    clf, _, _ = build([(200, {}, lenient)])
    result = clf.classify("x = 1", questions)
    assert result.answers["secret"].probability == 0.25 and result.answers["worst"].choice == "none"

    # 9. size and configuration are checked before any network call
    clf, net, _ = build([(200, {}, good)])
    fails(StateTooLarge, lambda: clf.classify("x = 1\n" * 20_000, questions))
    assert net.calls == []
    unconfigured = Decision1Classifier(endpoint="", api_key="", transport=Net([(200, {}, good)]))
    fails(ClassifierError, lambda: unconfigured.classify("x = 1", questions))
    fails(ValueError, lambda: clf.classify("x = 1", []))             # malformed questions are the caller's bug, not the provider's

    # 10. from_env reads the deployment and version
    saved = {k: os.environ.get(k) for k in ("DECISION1_DEPLOYMENT", "DECISION1_MODEL_VERSION", "FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY")}
    try:
        os.environ.update(DECISION1_DEPLOYMENT="my-dec", DECISION1_MODEL_VERSION="2", FOUNDRY_ENDPOINT="https://r.services.ai.azure.com/", FOUNDRY_API_KEY=KEY)
        net = Net([(200, {}, good)])
        from_env = Decision1Classifier.from_env(transport=net)
        assert from_env.classify("x = 1", questions).model == "Microsoft-Decision-1@2"
        assert json.loads(net.calls[0]["body"])["model"] == "my-dec" and net.calls[0]["url"].startswith("https://r.services.ai.azure.com/providers/")
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)

    print("adapters.decision1 OK: request shape, masking, retries, rejection, strict reply checks, no leaks (mock network only)")


if __name__ == "__main__":
    demo()
