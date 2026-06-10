from __future__ import annotations

import requests
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from pyshare.core.config import settings

_client: OpenAI | None = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        if not settings.llm_api_key:
            raise RuntimeError("OPENROUTER_API_KEY is not set")
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
