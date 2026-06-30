from __future__ import annotations

import requests
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

from pyshare_core.config import settings

if TYPE_CHECKING:
    from openai import OpenAI


_client: Any | None = None


def get_client() -> Any:
    global _client
    if _client is None:
        if not settings.llm_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "openai is required for LLM chat calls; install the server extra"
            ) from exc
        default_headers = {}
        if settings.openrouter_http_referer:
            default_headers["HTTP-Referer"] = settings.openrouter_http_referer
        if settings.openrouter_app_title:
            default_headers["X-OpenRouter-Title"] = settings.openrouter_app_title
        _client = OpenAI(
            api_key=settings.llm_api_key,
            base_url=settings.llm_base_url,
            default_headers=default_headers,
        )
    return _client


def openrouter_headers() -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
    }
    if settings.openrouter_http_referer:
        headers["HTTP-Referer"] = settings.openrouter_http_referer
    if settings.openrouter_app_title:
        headers["X-OpenRouter-Title"] = settings.openrouter_app_title
    return headers


def rerank(
    *,
    query: str,
    documents: list[str],
    model: str,
    top_n: int | None = None,
) -> list[tuple[int, float]]:
    if not settings.openrouter_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    try:
        response = requests.post(
            f"{settings.llm_base_url}/rerank",
            headers=openrouter_headers(),
            json={
                "model": model,
                "query": query,
                "documents": documents,
                "top_n": top_n or len(documents),
            },
            timeout=90,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"OpenRouter rerank request failed: {exc}") from exc
    if response.status_code != 200:
        raise RuntimeError(
            f"OpenRouter rerank returned HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
    payload = response.json()
    return [
        (int(item["index"]), float(item["relevance_score"]))
        for item in payload.get("results", [])
        if "index" in item and "relevance_score" in item
    ]


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
