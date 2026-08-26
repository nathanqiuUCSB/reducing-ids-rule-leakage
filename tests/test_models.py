import pytest

from hardening_game.models import load_litellm_models


def test_litellm_model_loader_uses_openai_compatible_endpoint() -> None:
    observed: dict[str, object] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> object:
            return {"data": [{"id": "model-b"}, {"id": "model-a"}]}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, url: str, *, headers: dict[str, str]) -> Response:
            observed["url"] = url
            observed["headers"] = headers
            return Response()

    assert load_litellm_models(
        "secret",
        base_url="https://example.test/v1",
        client_factory=lambda **kwargs: Client(),
    ) == ["model-a", "model-b"]
    assert observed["url"] == "https://example.test/v1/models"
    assert observed["headers"] == {"Authorization": "Bearer secret"}


def test_litellm_model_loader_requires_key() -> None:
    with pytest.raises(ValueError, match="LITELLM_API_KEY"):
        load_litellm_models("", base_url="https://example.test/v1")
