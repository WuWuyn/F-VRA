from __future__ import annotations

import json

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from pyshare.core.config import settings


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def embed_batch(texts: list[str], model: str | None = None) -> list[list[float]]:
    if not settings.llm_api_key:
        raise RuntimeError(
            f"API key for provider '{settings.llm_provider}' is not set. "
            "Set OPENAI_API_KEY or OPENROUTER_API_KEY in .env."
        )

    base_url = settings.llm_base_url or "https://api.openai.com/v1"
    resp = requests.post(
        base_url.rstrip("/") + "/embeddings",
        headers={
            "Authorization": f"Bearer {settings.llm_api_key}",
            "Content-Type": "application/json",
        },
        json={"model": model or settings.embedding_model, "input": texts},
        timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Embedding API {resp.status_code}: {resp.text[:300]}")

    body = json.loads(resp.text.strip())
    data = body.get("data") or []
    if not data:
        raise RuntimeError(f"Embedding API returned no data: {resp.text[:300]}")
    return [d["embedding"] for d in data]


def describe() -> str:
    return (
        f"provider={settings.llm_provider} "
        f"embedding_model={settings.embedding_model} "
        f"base_url={settings.llm_base_url}"
    )
