"""
security_service/adapters/llm_clients.py

Generic LLMClient adapters:
  CallableLLM(name, fn) - wrap any vendor SDK in a few lines:
        def ask(system, user): ...        # return a dict or JSON text
        llm = CallableLLM("vendor:model", ask)
  FakeLLM(...)          - scripted answers for tests; never touches a network.
"""

from __future__ import annotations

from typing import Any, Callable

from security_service.ports.llm import parse_json_object


class CallableLLM:
    def __init__(self, name: str, fn: Callable[[str, str], dict | str]):
        self.name = name
        self._fn = fn

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        result = self._fn(system, user)
        return result if isinstance(result, dict) else parse_json_object(result)


class FakeLLM:
    """Scripted answers, in order (the last one repeats). An Exception instance is raised instead of returned."""

    def __init__(self, responses: list[Any], name: str = "fake"):
        self.name = name
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.calls.append((system, user))
        index = min(len(self.calls) - 1, len(self._responses) - 1)
        response = self._responses[index]
        if isinstance(response, Exception):
            raise response
        return response if isinstance(response, dict) else parse_json_object(response)


def demo() -> None:
    fake = FakeLLM([{"n": 1}, RuntimeError("boom")])
    assert fake.complete_json("s", "u") == {"n": 1}
    try:
        fake.complete_json("s", "u")
        raise AssertionError("expected the scripted error")
    except RuntimeError:
        pass
    assert len(fake.calls) == 2
    assert CallableLLM("v:m", lambda s, u: '{"ok": true}').complete_json("s", "u") == {"ok": True}
    assert FakeLLM(['```json\n{"x": 2}\n```']).complete_json("s", "u") == {"x": 2}
    print("adapters.llm_clients OK: callable and scripted clients")


if __name__ == "__main__":
    demo()
