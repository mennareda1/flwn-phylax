"""
security_service/ports/classifier.py

Port: typed-question classification, the role a decision model such as Microsoft-Decision-1 plays.

The core asks a set of named questions about one piece of code and gets probabilities back. It
never sees a provider's wire format: an adapter maps these types to the vendor's API and back.
Rules for any adapter:
  - answers must come back keyed by the question ids that were sent;
  - `model` must be the exact versioned model id that answered (never an alias like "latest"; for
    Microsoft-Decision-1 that is the model name plus the version chosen when the deployment was
    created, for example "Microsoft-Decision-1@1"), so every result can be traced and confidence
    thresholds can be tuned against one version;
  - the provider's own limits (context size, rate limits) are the adapter's problem, surfaced as
    exceptions or via max_state_tokens, never as a change to this interface;
  - failures are raised as the ClassifierError family below, never returned as partial answers,
    and never carry the submitted code or a credential in their message.

Failure meanings (the scan service treats every ClassifierError as a failed engine, so a scan can
fail closed but never silently pass):
  ClassifierUnavailable  trouble that outlasted the adapter's retries (timeouts, rate limits, 5xx)
  ClassifierRejected     the provider refused the request (bad key, bad question); retrying won't help
  StateTooLarge          the code does not fit one question; the caller must chunk it first

A classifier's answers are a SIGNAL. The decision policy (core/policy.py) keeps its veto until
the classifier passes the promotion test on the benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

MAX_CHOICE_OPTIONS = 255


class ClassifierError(RuntimeError):
    """Base class for every classifier failure."""


class ClassifierUnavailable(ClassifierError):
    """Transient trouble that outlasted the adapter's retries."""


class ClassifierRejected(ClassifierError):
    """The provider refused the request; retrying will not help."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status     # the HTTP status when there is one; 400 and 422 mean "this request shape is not accepted"


class StateTooLarge(ClassifierError):
    """The code does not fit in one question; chunk it before asking."""


@dataclass(frozen=True)
class Question:
    id: str
    kind: Literal["yes_no", "choice"]
    instructions: str                         # write the exact condition; models read literally
    # choice: option -> description. yes_no: optionally {"true": ..., "false": ...}, which sharpens borderline cases
    options: dict[str, str] | None = None


@dataclass(frozen=True)
class Answer:
    kind: Literal["yes_no", "choice"]
    probability: float | None = None          # yes_no: probability of yes, 0..1
    choice: str | None = None                 # choice: the most likely option
    probabilities: dict[str, float] | None = None
    confidence: float | None = None           # how certain the model is; None if the provider gives none


@dataclass(frozen=True)
class ClassifierResult:
    answers: dict[str, Answer]
    model: str                                # exact versioned id that answered
    input_tokens: int = 0


class Classifier(Protocol):
    role: str                                 # "classifier"
    name: str
    max_state_tokens: int                     # largest code size, in tokens, one question accepts

    def classify(self, state: str, questions: list[Question]) -> ClassifierResult:
        """Answer every question about `state`. Raise on any failure; never return partial answers."""
        ...


def validate_questions(questions: list[Question]) -> None:
    if not questions:
        raise ValueError("at least one question is required")
    seen: set[str] = set()
    for q in questions:
        if not q.id or q.id in seen:
            raise ValueError(f"question ids must be non-empty and unique (got {q.id!r})")
        seen.add(q.id)
        if not q.instructions.strip():
            raise ValueError(f"question {q.id!r} has no instructions")
        if q.kind == "choice":
            if not q.options or len(q.options) < 2:
                raise ValueError(f"choice question {q.id!r} needs at least two options")
            if len(q.options) > MAX_CHOICE_OPTIONS:
                raise ValueError(f"choice question {q.id!r} has more than {MAX_CHOICE_OPTIONS} options")
        elif q.kind == "yes_no":
            if q.options is not None and (set(q.options) != {"true", "false"} or not all(isinstance(v, str) and v.strip() for v in q.options.values())):
                raise ValueError(f"yes/no question {q.id!r} may only carry the options 'true' and 'false', each with a description")
        else:
            raise ValueError(f"question {q.id!r} is malformed")


def validate_result(questions: list[Question], result: ClassifierResult) -> None:
    """What the core checks on every adapter's reply before trusting it."""
    sent = {q.id: q for q in questions}
    if set(result.answers) != set(sent):
        raise ValueError(f"answers {sorted(result.answers)} do not match questions {sorted(sent)}")
    if not result.model or result.model.endswith(("latest", "preview")):
        raise ValueError(f"adapter must report an exact model version, got {result.model!r}")
    for qid, answer in result.answers.items():
        if answer.kind != sent[qid].kind:
            raise ValueError(f"answer {qid!r} has the wrong kind")
        if answer.kind == "yes_no":
            if answer.probability is None or not 0.0 <= answer.probability <= 1.0:
                raise ValueError(f"answer {qid!r} needs a probability between 0 and 1")
        else:
            if answer.choice not in (sent[qid].options or {}):
                raise ValueError(f"answer {qid!r} chose an option that was not offered")


def demo() -> None:
    q_yes = Question("shell", "yes_no", "Does the code pass a variable into a shell command?")
    q_pick = Question("kind", "choice", "Which weakness is most likely?", {"sqli": "SQL injection", "none": "No weakness"})
    validate_questions([q_yes, q_pick])
    validate_questions([Question("c", "yes_no", "Is it?", {"true": "it is", "false": "it is not"})])     # optional criteria on a yes/no
    for bad_criteria in ({"true": "only one"}, {"yes": "a", "no": "b"}, {"true": "a", "false": "  "}):
        try:
            validate_questions([Question("c", "yes_no", "Is it?", bad_criteria)])
            raise AssertionError(f"expected rejection of criteria {bad_criteria!r}")
        except ValueError:
            pass

    for bad in ([], [q_yes, q_yes], [Question("c", "choice", "x", {"only": "one"})],
                [Question("e", "yes_no", "  ")], [Question("m", "yes_no", "x", {"a": "b"})]):
        try:
            validate_questions(bad)
            raise AssertionError(f"expected rejection of {bad!r}")
        except ValueError:
            pass

    good = ClassifierResult(
        {"shell": Answer("yes_no", probability=0.92), "kind": Answer("choice", choice="none", probabilities={"sqli": 0.1, "none": 0.9}, confidence=0.8)},
        model="Microsoft-Decision-1@1")
    validate_result([q_yes, q_pick], good)

    broken = {
        "missing answer": ClassifierResult({"shell": good.answers["shell"]}, "Microsoft-Decision-1@1"),
        "alias instead of version": ClassifierResult(good.answers, "decision-latest"),
        "probability out of range": ClassifierResult({**good.answers, "shell": Answer("yes_no", probability=1.4)}, "Microsoft-Decision-1@1"),
        "option not offered": ClassifierResult({**good.answers, "kind": Answer("choice", choice="xss")}, "Microsoft-Decision-1@1"),
        "wrong kind": ClassifierResult({**good.answers, "shell": Answer("choice", choice="none")}, "Microsoft-Decision-1@1"),
    }
    for label, result in broken.items():
        try:
            validate_result([q_yes, q_pick], result)
            raise AssertionError(f"expected rejection: {label}")
        except ValueError:
            pass
    assert issubclass(ClassifierUnavailable, ClassifierError) and issubclass(ClassifierRejected, ClassifierError)
    assert issubclass(StateTooLarge, ClassifierError) and issubclass(ClassifierError, RuntimeError)
    print("ports.classifier OK: question and reply validation, exact model versions required, failure family defined")


if __name__ == "__main__":
    demo()
