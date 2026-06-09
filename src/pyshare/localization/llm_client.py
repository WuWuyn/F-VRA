from __future__ import annotations

from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from pyshare.core.config import settings

_client: OpenAI | None = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        if not settings.llm_api_key:
            raise RuntimeError(
                f"API key for provider '{settings.llm_provider}' is not set. "
                "Set OPENAI_API_KEY or OPENROUTER_API_KEY in .env."
            )
        _client = OpenAI(api_key=settings.llm_api_key, base_url=settings.llm_base_url)
    return _client


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def chat(messages: list[dict], model: str | None = None, temperature: float = 0.0) -> str:
    resp = get_client().chat.completions.create(
        model=model or settings.llm_model,
        messages=messages,
        temperature=temperature,
    )
    return resp.choices[0].message.content or ""


def describe() -> str:
    return (
        f"provider={settings.llm_provider} "
        f"model={settings.llm_model} "
        f"base_url={settings.llm_base_url}"
    )
