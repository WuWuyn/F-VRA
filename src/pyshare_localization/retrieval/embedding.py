from __future__ import annotations

import math
import time
from typing import Protocol

import requests
from tqdm import tqdm

from pyshare_core.config import settings
from pyshare_localization.providers.llm_client import provider_headers
from pyshare_localization.models import FunctionInfo


class EmbeddingBackend(Protocol):
    model_name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAICompatibleEmbeddingBackend:
    def __init__(
        self,
        *,
        model_name: str,
        api_key: str,
        base_url: str,
        provider_name: str,
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.provider_name = provider_name
        if not api_key:
            raise RuntimeError(f"{provider_name} embedding API key is not set")

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = None
        for attempt in range(3):
            try:
                payload = {
                    "model": self.model_name,
                    "input": texts,
                    "encoding_format": "float",
                }
                response = requests.post(
                    f"{self.base_url}/embeddings",
                    headers=provider_headers(self.api_key),
                    json=payload,
                    timeout=90,
                )
            except requests.RequestException as exc:
                if attempt == 2:
                    raise RuntimeError(f"{self.provider_name} embeddings request failed: {exc}") from exc
                time.sleep(2**attempt)
                continue
            if response.status_code == 200:
                break
            if response.status_code not in {429, 529} or attempt == 2:
                raise RuntimeError(
                    f"{self.provider_name} embeddings returned HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )
            time.sleep(2**attempt)

        if response is None:
            raise RuntimeError(f"{self.provider_name} embeddings request did not produce a response")
        payload = response.json()
        data = sorted(payload.get("data", []), key=lambda item: item.get("index", 0))
        if len(data) != len(texts):
            raise RuntimeError(
                f"{self.provider_name} embeddings returned {len(data)} vectors for {len(texts)} inputs"
            )
        return [item["embedding"] for item in data]


class LocalEmbeddingBackend(OpenAICompatibleEmbeddingBackend):
    def __init__(self, model_name: str | None = None) -> None:
        super().__init__(
            model_name=model_name or settings.local_embedding_model,
            api_key=settings.local_embedding_api_key or settings.local_llm_api_key,
            base_url=settings.local_embedding_base_url,
            provider_name="local",
        )


class AutoEmbeddingBackend:
    def __init__(self) -> None:
        backends: list[EmbeddingBackend] = []
        local_ready = bool(
            (settings.local_embedding_api_key or settings.local_llm_api_key)
            and settings.local_embedding_base_url
            and settings.local_embedding_model
        )
        if local_ready:
            backends.append(LocalEmbeddingBackend())
        if not backends:
            raise RuntimeError(
                "No embedding API key is set; configure LOCAL_EMBEDDING_API_KEY, "
                "or LOCAL_LLM_API_KEY"
            )
        self.backends = backends
        self.model_name = backends[0].model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        errors: list[str] = []
        for backend in self.backends:
            try:
                vectors = backend.embed(texts)
                self.model_name = backend.model_name
                return vectors
            except RuntimeError as exc:
                errors.append(f"{getattr(backend, 'model_name', 'unknown')}: {exc}")
        raise RuntimeError("All embedding providers failed: " + " | ".join(errors))


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

    active_backend = backend or AutoEmbeddingBackend()
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
