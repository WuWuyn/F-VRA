from __future__ import annotations

import math

from tqdm import tqdm

from pyshare.core.config import settings
from pyshare.localization.embedding_client import embed_batch


def _truncate(text: str, max_chars: int = 3000) -> str:
    return text if len(text) <= max_chars else text[:max_chars]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb)
    return dot / denom if denom > 0 else 0.0


def rerank_with_embedding(description: str, funcs: list[dict], top_k: int | None = None) -> list[dict]:
    if not funcs:
        return []

    query_embedding = embed_batch([description])[0]
    function_texts = [
        _truncate(func["body"] + "\n# docstring: " + (func.get("docstring") or ""))
        for func in funcs
    ]

    function_embeddings: list[list[float]] = []
    for start in tqdm(
        range(0, len(function_texts), settings.embedding_batch_size),
        desc="Embedding functions",
    ):
        batch = function_texts[start : start + settings.embedding_batch_size]
        function_embeddings.extend(embed_batch(batch))

    scored = [
        {**func, "embedding_score": _cosine(query_embedding, function_embeddings[i])}
        for i, func in enumerate(funcs)
    ]
    scored.sort(
        key=lambda item: (item["embedding_score"], item.get("bm25_score", 0.0)),
        reverse=True,
    )
    return scored[: top_k or settings.llm_top_k]
