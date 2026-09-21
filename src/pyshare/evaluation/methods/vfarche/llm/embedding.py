"""Embedding wrapper that uses raw HTTP instead of the OpenAI SDK.

OpenRouter sometimes returns valid JSON prefixed with whitespace / heartbeat
padding, which makes the OpenAI SDK raise "No embedding data received".
Calling /embeddings ourselves via `requests` is more reliable.
"""
import json

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from pyshare.evaluation.methods.vfarche.config import EMBEDDING_MODEL, EMBEDDING_API_KEY, EMBEDDING_BASE_URL, LLM_PROVIDER
from .usage import record


@retry(retry=retry_if_exception_type(requests.RequestException),
       stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10), reraise=True)
def embed_batch(texts: list[str], model: str | None = None) -> list[list[float]]:
    """POST /embeddings, return list of float vectors (one per input text)."""
    if not EMBEDDING_API_KEY:
        raise RuntimeError(
            f"API key for provider '{LLM_PROVIDER}' is not set. "
            f"Set OPENAI_API_KEY or OPENROUTER_API_KEY in .env."
        )

    url = EMBEDDING_BASE_URL.rstrip("/") + "/embeddings"
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {EMBEDDING_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"model": model or EMBEDDING_MODEL, "input": texts},
        timeout=60,
    )
    if resp.status_code == 429 or resp.status_code >= 500:
        resp.raise_for_status()
    if resp.status_code != 200:
        raise RuntimeError(
            f"Embedding API HTTP {resp.status_code} at {url}, model={model or EMBEDDING_MODEL}. "
            "Check embedding model access and EMBEDDING_BASE_URL/EMBEDDING_API_KEY."
        )

    # Strip leading whitespace/heartbeat padding before parsing
    body = json.loads(resp.text.strip())
    record(body.get("usage"))
    data = body.get("data") or []
    if not data:
        raise RuntimeError(f"Embedding API returned no data: {resp.text[:300]}")
    if len(data) != len(texts) or sorted(d.get('index', -1) for d in data) != list(range(len(texts))):
        raise ValueError("Embedding response has missing/duplicate input indices")
    vectors = [d['embedding'] for d in sorted(data, key=lambda d: d['index'])]
    if not vectors[0] or len({len(v) for v in vectors}) != 1:
        raise ValueError("Embedding vectors are empty or have inconsistent dimensions")
    return vectors


def describe() -> str:
    return f"embedding_model={EMBEDDING_MODEL}  base_url={EMBEDDING_BASE_URL}"
