"""Embedding wrapper that uses raw HTTP instead of the OpenAI SDK.

OpenRouter sometimes returns valid JSON prefixed with whitespace / heartbeat
padding, which makes the OpenAI SDK raise "No embedding data received".
Calling /embeddings ourselves via `requests` is more reliable.
"""
import json

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from config import EMBEDDING_MODEL, LLM_API_KEY, LLM_BASE_URL, LLM_PROVIDER


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def embed_batch(texts: list[str], model: str | None = None) -> list[list[float]]:
    """POST /embeddings, return list of float vectors (one per input text)."""
    if not LLM_API_KEY:
        raise RuntimeError(
            f"API key cho provider '{LLM_PROVIDER}' chưa được set. "
            f"Set OPENAI_API_KEY hoặc OPENROUTER_API_KEY trong .env."
        )

    url = LLM_BASE_URL.rstrip("/") + "/embeddings"
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {LLM_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"model": model or EMBEDDING_MODEL, "input": texts},
        timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Embedding API {resp.status_code}: {resp.text[:300]}")

    # Strip leading whitespace/heartbeat padding before parsing
    body = json.loads(resp.text.strip())
    data = body.get("data") or []
    if not data:
        raise RuntimeError(f"Embedding API returned no data: {resp.text[:300]}")
    return [d["embedding"] for d in data]


def describe() -> str:
    return f"provider={LLM_PROVIDER}  embedding_model={EMBEDDING_MODEL}  base_url={LLM_BASE_URL}"
