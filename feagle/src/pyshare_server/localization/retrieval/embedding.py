from __future__ import annotations

import math
import time
from typing import Protocol

import requests
from tqdm import tqdm

from pyshare_core.config import settings
from pyshare_server.localization.providers.llm_client import openrouter_headers
from pyshare_server.localization.models import FunctionInfo


class EmbeddingBackend(Protocol):
    model_name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenRouterEmbeddingBackend:
    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or settings.openrouter_embedding_model
        if not settings.openrouter_api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set; semantic retrieval is unavailable"
            )

    def embed(self, texts: list[str]) -> list[list[float]]:
        headers = openrouter_headers()

        response = None
        for attempt in range(3):
            try:
                response = requests.post(
                    "https://openrouter.ai/api/v1/embeddings",
                    headers=headers,
                    json={
                        "model": self.model_name,
                        "input": texts,
                        "encoding_format": "float",
                        "provider": {"allow_fallbacks": True},
                    },
                    timeout=90,
                )
            except requests.RequestException as exc:
                if attempt == 2:
                    raise RuntimeError(f"OpenRouter embeddings request failed: {exc}") from exc
                time.sleep(2**attempt)
                continue
            if response.status_code == 200:
                break
            if response.status_code not in {429, 529} or attempt == 2:
                raise RuntimeError(
                    f"OpenRouter embeddings returned HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )
            time.sleep(2**attempt)

        if response is None:
            raise RuntimeError("OpenRouter embeddings request did not produce a response")
        payload = response.json()
        data = sorted(payload.get("data", []), key=lambda item: item.get("index", 0))
        if len(data) != len(texts):
            raise RuntimeError(
                f"OpenRouter embeddings returned {len(data)} vectors for {len(texts)} inputs"
            )
        return [item["embedding"] for item in data]


def function_embedding_text(function: FunctionInfo, max_chars: int = 4000) -> str:
    structural = " ".join(
        [
            function.qualname,
            function.file_path,
            " ".join(sorted(function.calls)),
            " ".join(function.decorators),
        ]
    )
    text = f"{structural}\n{function.docstring}\n{function.source}".strip()
    return text if len(text) <= max_chars else text[:max_chars]


def _cosine(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    denominator = left_norm * right_norm
    return dot / denominator if denominator else 0.0


def embedding_scores(
    description: str,
    functions: list[FunctionInfo],
    *,
    backend: EmbeddingBackend | None = None,
) -> tuple[dict[str, float], str]:
    if not functions:
        return {}, "not_run"

    active_backend = backend or OpenRouterEmbeddingBackend()
    texts = [description, *(function_embedding_text(function) for function in functions)]
    vectors: list[list[float]] = []
    batches = range(0, len(texts), settings.embedding_batch_size)
    for start in tqdm(batches, desc="Embedding batches"):
        vectors.extend(active_backend.embed(texts[start : start + settings.embedding_batch_size]))

    query_vector = vectors[0]
    scores = {
        function.identity: _cosine(query_vector, vectors[index + 1])
        for index, function in enumerate(functions)
    }
    return scores, active_backend.model_name
