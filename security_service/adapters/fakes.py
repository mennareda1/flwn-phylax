"""
security_service/adapters/fakes.py

Scripted classifier and corrector for tests and local development. They touch no network and
cost nothing, and they obey the same port rules as real adapters, so the conformance tests
that real adapters must pass are exercised against them first.
"""

from __future__ import annotations

from typing import Callable

from security_service.core.files import SourceFile
from security_service.core.patching import make_unified_diff
from security_service.core.schema import Finding
from security_service.ports.classifier import Answer, ClassifierResult, Question, validate_questions, validate_result
from security_service.ports.corrector import FixConstraints, Patch


class FakeClassifier:
    role = "classifier"
    max_state_tokens = 30_000

    def __init__(self, rule: Callable[[str, Question], Answer], name: str = "fake-classifier", model: str = "fake-1.0.0"):
        self.name = name
        self._rule = rule
        self._model = model
        self.calls: list[tuple[str, list[Question]]] = []

    def classify(self, state: str, questions: list[Question]) -> ClassifierResult:
        validate_questions(questions)
        self.calls.append((state, questions))
        return ClassifierResult({q.id: self._rule(state, q) for q in questions}, self._model, input_tokens=len(state.split()))


class FakeCorrector:
    """Replaces one piece of text with another in the file and returns the diff."""

    role = "corrector"

    def __init__(self, old: str, new: str, name: str = "fake-corrector"):
        self.name = name
        self._old, self._new = old, new

    def propose_fix(self, file: SourceFile, findings: list[Finding], constraints: FixConstraints) -> list[Patch]:
        if self._old not in file.content:
            return []
        fixed = file.content.replace(self._old, self._new)
        return [Patch(file.path, tuple(f.id for f in findings), make_unified_diff(file.path, file.content, fixed),
                      "Replaced the unsafe call with a safe one.")]


def demo() -> None:
    contains = lambda text: (lambda state, q: Answer("yes_no", probability=0.95 if text in state else 0.05))
    classifier = FakeClassifier(contains("os.system"))
    questions = [Question("shell", "yes_no", "Is a variable passed into a shell command?")]
    result = classifier.classify("os.system(cmd)", questions)
    validate_result(questions, result)
    assert result.answers["shell"].probability == 0.95 and len(classifier.calls) == 1
    safe = classifier.classify("print('hi')", questions)
    assert safe.answers["shell"].probability == 0.05

    corrector = FakeCorrector("os.system(cmd)", "subprocess.run(cmd, check=True)")
    patches = corrector.propose_fix(SourceFile("a.py", "os.system(cmd)\n"), [], FixConstraints())
    assert len(patches) == 1 and "+subprocess.run(cmd, check=True)" in patches[0].unified_diff
    assert corrector.propose_fix(SourceFile("b.py", "x = 1\n"), [], FixConstraints()) == []
    print("adapters.fakes OK: scripted classifier and corrector obey the port rules")


if __name__ == "__main__":
    demo()
