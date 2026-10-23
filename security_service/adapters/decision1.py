"""
security_service/adapters/decision1.py

Classifier adapter for Microsoft-Decision-1 on Microsoft Foundry.

What it does: sends one piece of code (the "state") plus named yes/no or pick-one questions to
    POST <foundry-resource-endpoint>/providers/microsoft/v1/systemone
and returns typed answers with probabilities, in the shape the classifier port defines.

Configuration comes from security_service.config (environment variables, optionally filled from a
.env file by the entry point; see .env.example). Build the adapter from it with:

    Decision1Classifier.from_settings(Settings.from_env())      # or simply Decision1Classifier.from_env()

Variables: FOUNDRY_ENDPOINT (or DECISION1_ENDPOINT), FOUNDRY_API_KEY (or DECISION1_API_KEY),
DECISION1_DEPLOYMENT (the name you chose in Foundry, NOT "Microsoft-Decision-1"), DECISION1_MODEL_VERSION,
DECISION1_AUTH ("key" or "entra"; Entra needs `pip install azure-identity` and `az login`),
DECISION1_TIMEOUT, DECISION1_MAX_ATTEMPTS. The endpoint may be the resource host or the full
.../providers/microsoft/v1/systemone URL; the path is stripped. Constructor arguments always win over
the environment, even an empty one.

Behavior worth knowing:
  - Secrets are masked inside this adapter before anything is sent (core/redaction.py), as the last
    line of defense at the boundary where code leaves the system. Masking is idempotent.
  - Only transient failures are retried (HTTP 408, 429, 500, 502, 503, 504 and network errors), up
    to 3 attempts, honoring Retry-After (capped at 10 s). Anything else fails at once.
  - Errors never contain the submitted code or any credential.
  - No new dependency: it uses urllib. The network call is injectable, so tests need no network.

CHECKED AGAINST MICROSOFT'S PAGE (Deploy and use Microsoft-Decision-1 in Microsoft Foundry, updated
2026-10-09): the endpoint path, the request shape (model = the DEPLOYMENT name, state, questions keyed
by name, each noul / choice / score with instructions and criteria), both authentication methods
(Entra ID bearer token, or an api-key header), and the error causes for 400, 401, 403, 404, 422, 429.

CONFIRMED BY A REAL CALL (2026-10-23, API-key sign-in, deployment "decision-1"): the reply is
    {"model": "microsoft-decision-1",
     "answers": {"<question>": {"type": "noul",   "noul": <probability>},
                 "<question>": {"type": "choice", "choice": "<option>", "confidence": <number>,
                                "probabilities": {"<option>": <probability>, ...}}},
     "usage": {"input_tokens": <n>, "output_tokens": <n>}}
That exact reply is kept as a regression test below (REAL_REPLY). Parsing stays tolerant about field
names, but strict about meaning. `confidence` is not the same number as the top probability.

STILL NOT SHOWN ANYWHERE: an input-size limit and a rate limit (max_state_tokens below is a cautious
guess), and whether an EU data zone is offered for this model.
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from security_service.config import SYSTEMONE_PATH, Settings, normalize_endpoint   # normalize_endpoint is re-exported
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
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
MAX_RETRY_WAIT_SECONDS = 10.0

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


ENTRA_SCOPE = "https://cognitiveservices.azure.com/.default"


def azure_token_provider(credential: Any | None = None) -> Callable[[], str]:
    """A bearer-token function for Microsoft Entra ID, the method Microsoft recommends.

    `credential` is anything with get_token(scope).token (tests pass a fake). By default it uses
    azure-identity's DefaultAzureCredential, which caches tokens, so calling this per request is fine."""
    if credential is None:
        try:
            from azure.identity import DefaultAzureCredential   # optional: pip install azure-identity
        except ImportError:
            raise ClassifierError("Entra authentication needs the azure-identity package: pip install azure-identity") from None
        credential = DefaultAzureCredential()
    return lambda: credential.get_token(ENTRA_SCOPE).token


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
    def from_settings(cls, settings: Settings, **overrides: Any) -> "Decision1Classifier":
        if settings.decision1_auth == "entra" and "token_provider" not in overrides:
            overrides["token_provider"] = azure_token_provider()   # built only when needed: it imports azure-identity
        arguments: dict[str, Any] = dict(
            deployment=settings.decision1_deployment,
            model_version=settings.decision1_model_version,
            endpoint=settings.decision1_endpoint,
            api_key=settings.decision1_api_key,
            timeout=settings.decision1_timeout,
            max_attempts=settings.decision1_max_attempts,
        )
        arguments.update(overrides)
        return cls(**arguments)

    @classmethod
    def from_env(cls, **overrides: Any) -> "Decision1Classifier":
        """Read the process environment only. (A .env file is loaded by entry points, not here.)"""
        return cls.from_settings(Settings.from_env(), **overrides)

    @property
    def url(self) -> str:
        """The exact URL requests go to."""
        return self._endpoint + SYSTEMONE_PATH

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
            body = {"type": "noul", "instructions": question.instructions}
            if question.options:                                    # optional: spell out what true and false mean
                body["criteria"] = {"true": question.options["true"], "false": question.options["false"]}
            return body
        return {"type": "choice", "instructions": question.instructions, "criteria": dict(question.options or {})}

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token_provider is not None:
            headers["Authorization"] = f"Bearer {self._token_provider()}"
        else:
            headers["api-key"] = self._api_key
        return headers

    def _post(self, payload: bytes) -> bytes:
        url = self.url
        last, last_status = "no attempt made", None
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
                last, last_status = f"HTTP {status}", status
            if attempt < self._max_attempts:
                self._sleep(self._delay(attempt, reply_headers))
        hint = "; the deployment's rate limit was exceeded: add capacity or lower the request rate" if last_status == 429 else ""
        raise ClassifierUnavailable(f"{MODEL_NAME} unavailable after {self._max_attempts} attempts (last: {last}){hint}")

    @staticmethod
    def _delay(attempt: int, headers: dict) -> float:
        retry_after = str(headers.get("retry-after", "")).strip()
        if retry_after.isdigit():
            return min(float(retry_after), MAX_RETRY_WAIT_SECONDS)
        return 0.5 * 2 ** (attempt - 1)

    _HINTS = {
        400: "the request has an invalid question type or shape",
        401: "the credential is missing, invalid or expired",
        403: "the identity has no access to the deployment; check its role assignment",
        404: "the endpoint or API path is wrong; use the resource endpoint from the deployment details page",
        422: "the deployment name or a question definition is not supported; the request's model must be the DEPLOYMENT name",
    }

    @staticmethod
    def _rejected(status: int, raw: bytes) -> ClassifierRejected:
        hint = Decision1Classifier._HINTS.get(status)
        suffix = f": {hint}" if hint else ""
        if status in (401, 403):
            return ClassifierRejected(f"authentication failed (HTTP {status}){suffix}", status=status)
        code = ""
        try:
            error = json.loads(raw).get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), str) and len(error["code"]) <= 60:
                code = f", code {error['code']}"
        except (ValueError, AttributeError):
            pass
        return ClassifierRejected(f"request rejected by the provider (HTTP {status}{code}){suffix}", status=status)

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
        self.last_raw = {"answers": answers_raw, "usage": usage, "model": data.get("model")}
        return result

    @staticmethod
    def _parse_answer(question: Question, item: Any) -> Answer:
        expected = "noul" if question.kind == "yes_no" else "choice"
        if isinstance(item, dict) and item.get("type") not in (None, expected):
            raise ClassifierError(f"answer for {question.id!r} has type {item.get('type')!r}, expected {expected!r}")

        if question.kind == "yes_no":
            if isinstance(item, dict):
                value = next((n for n in (_number(item.get(k)) for k in ("noul", "probability", "value")) if n is not None), None)
                if value is None and isinstance(item.get("probabilities"), dict):
                    value = _number(item["probabilities"].get("true"))
            else:
                value = _number(item)
            if value is None or not 0.0 <= value <= 1.0:
                raise ClassifierError(f"answer for {question.id!r} has no probability between 0 and 1")
            return Answer("yes_no", probability=value)

        if not isinstance(item, dict):
            raise ClassifierError(f"answer for {question.id!r} is not an object")
        raw_probabilities = item.get("probabilities") if isinstance(item.get("probabilities"), dict) else (
            item.get("probability") if isinstance(item.get("probability"), dict) else None)
        probabilities = None
        if raw_probabilities is not None:
            probabilities = {str(k): _number(v) for k, v in raw_probabilities.items()}
            if any(v is None or not 0.0 <= v <= 1.0 for v in probabilities.values()):
                raise ClassifierError(f"answer for {question.id!r} has an invalid probability")
        choice = item.get("choice")
        if choice is None and probabilities:
            choice = max(probabilities, key=probabilities.get)
        if not isinstance(choice, str) or choice not in (question.options or {}):
            raise ClassifierError(f"answer for {question.id!r} chose an option that was not offered")
        return Answer("choice", choice=choice, probabilities=probabilities, confidence=_number(item.get("confidence")))


# ---------------------------------------------------------------------- self-test

# A reply from the real service, captured 2026-10-23 from a live call (numbers unchanged). It guards the
# real format: if a future change stops this parsing, the check fails.
REAL_REPLY = {
    "model": "microsoft-decision-1",
    "answers": {
        "hardcoded_secret": {"noul": 0.6224621673326339, "type": "noul"},
        "shell_injection": {"noul": 0.7981875015706547, "type": "noul"},
        "worst_problem": {
            "choice": "command_injection",
            "confidence": 0.7735301735799088,
            "probabilities": {
                "cannot_tell": 0.0029939802866135895,
                "command_injection": 0.8301476301849317,
                "hardcoded_secret": 0.16346576539816604,
                "none": 0.003392624130288762,
            },
            "type": "choice",
        },
    },
    "usage": {"input_tokens": 163, "output_tokens": 3},
}


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

    # 11. the full API URL (as copied from the docs or the portal) works as the endpoint: the path is not doubled
    for pasted in ("https://res.services.ai.azure.com/providers/microsoft/v1/systemone",
                   "https://res.services.ai.azure.com/providers/microsoft/v1/systemone/"):
        assert normalize_endpoint(pasted) == "https://res.services.ai.azure.com", pasted
    net_full = Net([(200, {}, good)])
    Decision1Classifier(endpoint="https://res.services.ai.azure.com/providers/microsoft/v1/systemone", api_key=KEY,
                        transport=net_full).classify("x = 1", questions)
    assert net_full.calls[0]["url"] == URL, net_full.calls[0]["url"]

    # 12. reply shapes: Microsoft's page shows `type` and `choice`; a wrong type is an error, extra shapes are tolerated
    docs_style = {"model": "microsoft-decision-1", "usage": {"input_tokens": 12},
                  "answers": {"secret": {"type": "noul", "noul": 0.9},
                              "worst": {"type": "choice", "choice": "none", "probabilities": {"hardcoded_secret": 0.1, "command_injection": 0.1, "none": 0.7, "cannot_tell": 0.1}}}}
    clf, _, _ = build([(200, {}, docs_style)])
    result = clf.classify("x = 1", questions)
    assert result.answers["secret"].probability == 0.9 and result.answers["worst"].probabilities["none"] == 0.7
    assert clf.last_raw["model"] == "microsoft-decision-1" and result.model == "Microsoft-Decision-1@1"   # we report the version, the provider reports its own name
    nested = {"answers": {"secret": {"type": "noul", "probabilities": {"true": 0.8, "false": 0.2}},
                          "worst": {"type": "choice", "choice": "none", "probability": {"hardcoded_secret": 0.1, "command_injection": 0.1, "none": 0.7, "cannot_tell": 0.1}}}}
    clf, _, _ = build([(200, {}, nested)])
    result = clf.classify("x = 1", questions)
    assert result.answers["secret"].probability == 0.8 and result.answers["worst"].probabilities["none"] == 0.7
    for label, reply in {
        "choice answer to a yes/no question": {"answers": {**good["answers"], "secret": {"type": "choice", "choice": "none"}}},
        "noul answer to a choice question": {"answers": {**good["answers"], "worst": {"type": "noul", "noul": 0.5}}},
    }.items():
        clf, _, _ = build([(200, {}, reply)])
        assert "expected" in str(fails(ClassifierError, lambda: clf.classify("x = 1", questions))), label

    # 16. a yes/no question may carry true/false criteria, which are sent as Microsoft documents; the rejection carries its HTTP status
    with_criteria = [Question("p", "yes_no", "Is there a problem?", {"true": "There is a problem", "false": "There is none"})]
    net_c = Net([(200, {}, {"answers": {"p": {"type": "noul", "noul": 0.5}}})])
    build_c = Decision1Classifier(endpoint="https://res.services.ai.azure.com", api_key=KEY, transport=net_c)
    build_c.classify("x = 1", with_criteria)
    assert json.loads(net_c.calls[0]["body"])["questions"]["p"] == {"type": "noul", "instructions": "Is there a problem?", "criteria": {"true": "There is a problem", "false": "There is none"}}
    for status in (400, 422, 401):
        clf, _, _ = build([(status, {}, b"{}")])
        assert fails(ClassifierRejected, lambda: clf.classify("x = 1", questions)).status == status

    # 13. each error carries Microsoft's documented cause, still without leaking anything
    for status, needle in ((404, "endpoint or API path"), (422, "DEPLOYMENT name"), (403, "role assignment"),
                           (400, "invalid question type"), (401, "expired")):
        clf, net, _ = build([(status, {}, b'{"error": {"message": "echo SuperSecret123"}}')])
        err = fails(ClassifierRejected, lambda: clf.classify(SECRET_STATE, questions))
        assert needle in str(err) and f"HTTP {status}" in str(err) and len(net.calls) == 1, (status, str(err))
    clf, _, _ = build([(429, {}, b"")] * 3)
    assert "rate limit" in str(fails(ClassifierUnavailable, lambda: clf.classify(SECRET_STATE, questions)))

    # 14. Entra ID: the provider asks for the right scope; Bearer is sent; the key is not needed
    class FakeCredential:
        def __init__(self):
            self.scopes = []

        def get_token(self, scope):
            self.scopes.append(scope)
            return type("Token", (), {"token": "entra-token-xyz"})()

    credential = FakeCredential()
    provider = azure_token_provider(credential)
    assert provider() == "entra-token-xyz" and credential.scopes == ["https://cognitiveservices.azure.com/.default"]
    net_entra = Net([(200, {}, good)])
    Decision1Classifier(endpoint="https://res.services.ai.azure.com", token_provider=provider, transport=net_entra).classify("x = 1", questions)
    assert net_entra.calls[0]["headers"]["Authorization"] == "Bearer entra-token-xyz" and "api-key" not in net_entra.calls[0]["headers"]
    saved_ident = sys.modules.get("azure.identity", "absent")
    sys.modules["azure.identity"] = None                    # simulate the package not being installed, whatever this machine has
    try:
        assert "pip install azure-identity" in str(fails(ClassifierError, lambda: azure_token_provider()))
    finally:
        if saved_ident == "absent":
            sys.modules.pop("azure.identity", None)
        else:
            sys.modules["azure.identity"] = saved_ident

    # 15. the REAL reply captured from Microsoft's service parses into exactly the values it contained
    real_questions = [
        Question("hardcoded_secret", "yes_no", "Does the code contain a hardcoded password, key or token?"),
        Question("shell_injection", "yes_no", "Does the code build a shell command from a variable?"),
        Question("worst_problem", "choice", "Which is the most serious security problem in this code?",
                 {"hardcoded_secret": "a secret", "command_injection": "a shell", "none": "nothing", "cannot_tell": "unclear"}),
    ]
    clf, _, _ = build([(200, {}, REAL_REPLY)])
    real = clf.classify("x = 1", real_questions)
    validate_result(real_questions, real)
    assert real.answers["hardcoded_secret"].probability == 0.6224621673326339
    assert real.answers["shell_injection"].probability == 0.7981875015706547
    worst = real.answers["worst_problem"]
    assert worst.choice == "command_injection" and worst.confidence == 0.7735301735799088
    assert worst.probabilities["hardcoded_secret"] == 0.16346576539816604 and abs(sum(worst.probabilities.values()) - 1.0) < 1e-9
    assert real.input_tokens == 163 and real.model == "Microsoft-Decision-1@1" and clf.last_raw["model"] == "microsoft-decision-1"
    assert worst.confidence != worst.probabilities["command_injection"]          # confidence is its own number, not the top probability

    # 10. settings drive the adapter: deployment, version, timeout, attempts; a pasted full URL works; own endpoint and key win
    env = {"FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com/providers/microsoft/v1/systemone", "FOUNDRY_API_KEY": KEY,
           "DECISION1_DEPLOYMENT": "my-dec", "DECISION1_MODEL_VERSION": "2", "DECISION1_TIMEOUT": "5", "DECISION1_MAX_ATTEMPTS": "2"}
    net = Net([(200, {}, good)])
    via_settings = Decision1Classifier.from_settings(Settings.from_env(env), transport=net)
    assert via_settings.classify("x = 1", questions).model == "Microsoft-Decision-1@2"
    assert json.loads(net.calls[0]["body"])["model"] == "my-dec"
    assert net.calls[0]["url"] == "https://r.services.ai.azure.com/providers/microsoft/v1/systemone"
    assert net.calls[0]["timeout"] == 5.0 and net.calls[0]["headers"]["api-key"] == KEY
    net = Net([(503, {}, b"")])
    fails(ClassifierUnavailable, lambda: Decision1Classifier.from_settings(Settings.from_env(env), transport=net, sleep=lambda s: None).classify("x = 1", questions))
    assert len(net.calls) == 2                                  # DECISION1_MAX_ATTEMPTS=2 was honored
    net = Net([(200, {}, good)])
    Decision1Classifier.from_settings(Settings.from_env({**env, "DECISION1_ENDPOINT": "https://own.services.ai.azure.com", "DECISION1_API_KEY": "own-key"}), transport=net).classify("x = 1", questions)
    assert net.calls[0]["url"].startswith("https://own.services.ai.azure.com/") and net.calls[0]["headers"]["api-key"] == "own-key"
    net = Net([(200, {}, good)])
    entra_env = {"FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com", "DECISION1_AUTH": "entra"}   # no key at all
    Decision1Classifier.from_settings(Settings.from_env(entra_env), transport=net, token_provider=lambda: "tok-env").classify("x = 1", questions)
    assert net.calls[0]["headers"]["Authorization"] == "Bearer tok-env" and "api-key" not in net.calls[0]["headers"]

    # from_env() reads the real process environment: clear every variable the project reads first, so this
    # check gives the same answer whatever a developer has in their terminal
    from security_service.config import VARIABLES
    saved = {name: os.environ.pop(name, None) for name in VARIABLES}
    try:
        os.environ.update({"FOUNDRY_ENDPOINT": "https://r.services.ai.azure.com/", "FOUNDRY_API_KEY": KEY, "DECISION1_DEPLOYMENT": "from-process"})
        net = Net([(200, {}, good)])
        Decision1Classifier.from_env(transport=net).classify("x = 1", questions)
        assert json.loads(net.calls[0]["body"])["model"] == "from-process" and net.calls[0]["headers"]["api-key"] == KEY
    finally:
        for name in VARIABLES:
            os.environ.pop(name, None)
        os.environ.update({name: value for name, value in saved.items() if value is not None})

    print("adapters.decision1 OK: request shape, masking, retries, documented error causes, full-URL endpoint, Entra auth, strict reply checks, no leaks (mock network only)")


if __name__ == "__main__":
    demo()
