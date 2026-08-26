"""OpenAI-compatible LiteLLM model discovery."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

import httpx


class ModelResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> object: ...


class ModelClient(Protocol):
    def __enter__(self) -> "ModelClient": ...

    def __exit__(self, *args: object) -> None: ...

    def get(self, url: str, *, headers: dict[str, str]) -> ModelResponse: ...


ModelClientFactory = Callable[..., ModelClient]


def load_litellm_models(
    api_key: str,
    *,
    base_url: str,
    client_factory: ModelClientFactory = httpx.Client,
) -> list[str]:
    if not api_key:
        raise ValueError("Set LITELLM_API_KEY before loading models.")
    with client_factory(verify=False, timeout=20) as client:
        response = client.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    response.raise_for_status()
    payload = response.json()
    records = payload.get("data", []) if isinstance(payload, dict) else []
    identifiers = {
        record["id"].strip()
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("id"), str)
        and record["id"].strip()
    }
    return sorted(identifiers)
