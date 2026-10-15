"""
security_service/adapters/foundry_llm.py

LLMClient for an Azure AI Foundry deployment. Standalone: it uses its own
configuration and never imports Flwn code.

Configuration (constructor arguments win over environment variables):
    FOUNDRY_ENDPOINT   e.g. https://<resource>.services.ai.azure.com   (no trailing path)
    FOUNDRY_API_KEY

The call mirrors what Flwn's own structured_chat does, which is known to work with
your deployments: azure-ai-inference ChatCompletionsClient at "<endpoint>/models",
messages = system + user, model = deployment name, no max_tokens, no tools.

NOT YET RUN AGAINST A REAL ENDPOINT. Tested only with an injected fake client.
GPT-6 Astra notes (docs and a third-party test, both worth re-checking): Chat
Completions works without tool calling; tool calling needs the Responses API, so
this adapter must stay tool-free. If a reasoning model replies with empty content
it likely spent its token budget thinking, and parse_json_object raises.
"""

from __future__ import annotations

import os
from typing import Any

from security_service.ports.llm import parse_json_object


class FoundryLLM:
    def __init__(
        self,
        deployment: str,
        endpoint: str | None = None,
        api_key: str | None = None,
        client: Any | None = None,
    ):
        self.deployment = deployment
        self.name = f"foundry:{deployment}"
        self._endpoint = endpoint or os.getenv("FOUNDRY_ENDPOINT", "")
        self._api_key = api_key or os.getenv("FOUNDRY_API_KEY", "")
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._endpoint.strip() or not self._api_key.strip():
                raise RuntimeError("FOUNDRY_ENDPOINT and FOUNDRY_API_KEY are required")
            from azure.ai.inference import ChatCompletionsClient   # optional dependency
            from azure.core.credentials import AzureKeyCredential

            self._client = ChatCompletionsClient(
                endpoint=f"{self._endpoint.rstrip('/')}/models",
                credential=AzureKeyCredential(self._api_key),
            )
        return self._client

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        response = self._get_client().complete(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            model=self.deployment,
        )
        return parse_json_object(response.choices[0].message.content)


def demo() -> None:
    from types import SimpleNamespace

    seen = {}

    class FakeSdk:
        def complete(self, messages, model):
            seen.update(messages=messages, model=model)
            message = SimpleNamespace(content='<|START_TEXT|>{"findings": []}<|END_TEXT|>')
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    llm = FoundryLLM("gpt-6-astra", client=FakeSdk())
    assert llm.name == "foundry:gpt-6-astra"
    assert llm.complete_json("sys", "usr") == {"findings": []}
    assert seen["model"] == "gpt-6-astra"
    assert [m["role"] for m in seen["messages"]] == ["system", "user"]

    class EmptySdk:
        def complete(self, messages, model):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=""))])

    try:
        FoundryLLM("x", client=EmptySdk()).complete_json("s", "u")
        raise AssertionError("empty content must raise")
    except ValueError as exc:
        assert "empty" in str(exc)

    try:
        FoundryLLM("x", endpoint="", api_key="").complete_json("s", "u")
        raise AssertionError("missing config must raise")
    except RuntimeError as exc:
        assert "FOUNDRY_ENDPOINT" in str(exc)

    print("adapters.foundry_llm OK: request shape, empty-content and missing-config handling (fake SDK only)")


if __name__ == "__main__":
    demo()
