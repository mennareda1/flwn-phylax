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

from security_service.config import Settings, normalize_endpoint
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
        # An explicit argument always wins, even an empty one; the environment is only a fallback
        # for "not given" (None). This matches the Decision-1 adapter.
        self._endpoint = endpoint if endpoint is not None else os.getenv("FOUNDRY_ENDPOINT", "")
        self._api_key = api_key if api_key is not None else os.getenv("FOUNDRY_API_KEY", "")
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings, deployment: str) -> "FoundryLLM":
        return cls(deployment, endpoint=settings.foundry_endpoint, api_key=settings.foundry_api_key)

    def _base_url(self) -> str:
        """The chat endpoint. A pasted full URL (for example the Decision-1 one) is reduced to the resource host first."""
        return f"{normalize_endpoint(self._endpoint)}/models"

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._endpoint.strip() or not self._api_key.strip():
                raise RuntimeError("FOUNDRY_ENDPOINT and FOUNDRY_API_KEY are required")
            from azure.ai.inference import ChatCompletionsClient   # optional dependency
            from azure.core.credentials import AzureKeyCredential

            self._client = ChatCompletionsClient(
                endpoint=self._base_url(),
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

    # Missing configuration must raise even when REAL variables are set in the environment (an explicit
    # empty value beats the environment), so this check passes no matter what the terminal holds.
    saved = {k: os.environ.get(k) for k in ("FOUNDRY_ENDPOINT", "FOUNDRY_API_KEY")}
    try:
        os.environ["FOUNDRY_ENDPOINT"] = "https://leak.services.ai.azure.com"
        os.environ["FOUNDRY_API_KEY"] = "leak-key"
        try:
            FoundryLLM("x", endpoint="", api_key="").complete_json("s", "u")
            raise AssertionError("missing config must raise")
        except RuntimeError as exc:
            assert "FOUNDRY_ENDPOINT" in str(exc)
        # ...while "not given" does fall back to the environment
        assert FoundryLLM("x")._endpoint == "https://leak.services.ai.azure.com" and FoundryLLM("x")._api_key == "leak-key"
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)

    # a pasted Decision-1 URL must not leak into the chat endpoint
    assert FoundryLLM("x", endpoint="https://res.services.ai.azure.com/providers/microsoft/v1/systemone", api_key="k")._base_url() == "https://res.services.ai.azure.com/models"
    assert FoundryLLM("x", endpoint="https://res.services.ai.azure.com/", api_key="k")._base_url() == "https://res.services.ai.azure.com/models"
    from_cfg = FoundryLLM.from_settings(Settings.from_env({"FOUNDRY_ENDPOINT": "https://res.services.ai.azure.com/providers/microsoft/v1/systemone", "FOUNDRY_API_KEY": "kk"}), "gpt-6-astra")
    assert from_cfg._base_url() == "https://res.services.ai.azure.com/models" and from_cfg.name == "foundry:gpt-6-astra"

    print("adapters.foundry_llm OK: request shape, empty-content and missing-config handling, endpoint cleanup (fake SDK only)")


if __name__ == "__main__":
    demo()
