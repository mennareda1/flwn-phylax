"""
security_service/ports/llm.py

Port: "send a system + user prompt, get a JSON object back".

The LLM detector (and later the corrector) talk only to this interface, so any
vendor's model can sit behind it. Adapters live in adapters/: foundry_llm.py for
Azure Foundry deployments, llm_clients.py for a generic callable wrapper and a
scripted fake used in tests.

Code sent through any LLMClient must already have passed through
core.redaction.redact_secrets (the detector does this).
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol


class LLMClient(Protocol):
    name: str

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Return the model's answer as a JSON object. Raise on any failure."""
        ...


def parse_json_object(text: str) -> dict[str, Any]:
    """Tolerant parser: strips special tokens and code fences, then reads the first JSON object."""
    text = (text or "").replace("<|START_TEXT|>", "").replace("<|END_TEXT|>", "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).removesuffix("```").strip()
    if not text:
        raise ValueError("model returned empty content")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise ValueError("model reply contains no JSON object") from None
        parsed = json.loads(text[start:end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("model reply must be a JSON object")
    return parsed


def demo() -> None:
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('Sure! Here it is: {"a": 1} Hope that helps') == {"a": 1}
    assert parse_json_object('<|START_TEXT|>{"a": 1}<|END_TEXT|>') == {"a": 1}
    for bad in ("", "no json here", "[1, 2]"):
        try:
            parse_json_object(bad)
            raise AssertionError(f"expected failure for {bad!r}")
        except ValueError:
            pass
    print("ports.llm OK: tolerant JSON parsing")


if __name__ == "__main__":
    demo()
