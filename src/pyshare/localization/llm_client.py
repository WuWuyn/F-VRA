from __future__ import annotations

from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from pyshare.core.config import settings

_client: OpenAI | None = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        if not settings.llm_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set")
        default_headers = {"X-OpenRouter-Title": settings.openrouter_app_title}
        if settings.openrouter_http_referer:
            default_headers["HTTP-Referer"] = settings.openrouter_http_referer
        _client = OpenAI(
            api_key=settings.llm_api_key,
            base_url=settings.llm_base_url,
            default_headers=default_headers,
        )
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
        "provider=openrouter "
        f"model={settings.llm_model} "
        f"base_url={settings.llm_base_url}"
    )
