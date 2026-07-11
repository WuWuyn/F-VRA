from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

try:
    from tenacity import retry, stop_after_attempt, wait_exponential
except ImportError:
    def retry(*args: Any, **kwargs: Any):
        def decorator(func: Any) -> Any:
            return func

        return decorator

    def stop_after_attempt(*args: Any, **kwargs: Any) -> None:
        return None

    def wait_exponential(*args: Any, **kwargs: Any) -> None:
        return None

from pyshare.core.config import settings

if TYPE_CHECKING:
    from openai import OpenAI


_client: Any | None = None
_clients: dict[tuple[str, str], Any] = {}


@dataclass(frozen=True)
class ChatProvider:
    name: str
    api_key: str
    base_url: str
    model: str


def _configured_providers() -> list[ChatProvider]:
    local_key = settings.local_llm_api_key
    local = (
        ChatProvider(
            name="local",
            api_key=local_key,
            base_url=settings.local_llm_base_url,
            model=settings.local_llm_model,
        )
        if local_key and settings.local_llm_base_url and settings.local_llm_model
        else None
    )
    return [local] if local is not None else []


def chat_available() -> bool:
    return bool(_configured_providers())


def get_client() -> Any:
    global _client
    providers = _configured_providers()
    if not providers:
        raise RuntimeError("No LLM API key is set; configure LOCAL_LLM_API_KEY")
    provider = providers[0]
    if _client is None:
        _client = _client_for(provider)
    return _client


def _client_for(provider: ChatProvider) -> Any:
    key = (provider.name, provider.base_url)
    if key not in _clients:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "openai is required for LLM chat calls; install the server extra"
            ) from exc
        _clients[key] = OpenAI(
            api_key=provider.api_key,
            base_url=provider.base_url,
        )
    return _clients[key]


def provider_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def chat(messages: list[dict], model: str | None = None, temperature: float = 0.0) -> str:
    providers = _configured_providers()
    if not providers:
        raise RuntimeError("No LLM API key is set; configure LOCAL_LLM_API_KEY")

    errors: list[str] = []
    for index, provider in enumerate(providers):
        active_model = model if index == 0 and model else provider.model
        try:
            resp = _client_for(provider).chat.completions.create(
                model=active_model,
                messages=messages,
                temperature=temperature,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            errors.append(f"{provider.name}: {exc}")
            continue
    raise RuntimeError("LLM chat request failed for all providers: " + " | ".join(errors))


def describe() -> str:
    providers = _configured_providers()
    provider = providers[0] if providers else None
    return (
        f"provider={provider.name if provider else 'none'} "
        f"model={provider.model if provider else settings.llm_model} "
        f"base_url={provider.base_url if provider else settings.llm_base_url}"
    )
