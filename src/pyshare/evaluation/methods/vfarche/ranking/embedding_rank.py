import math

from tqdm import tqdm

from pyshare.evaluation.methods.vfarche.config import EMBEDDING_BATCH_SIZE, LLM_TOP_K
from pyshare.evaluation.methods.vfarche.llm.embedding import embed_batch


def _truncate(text: str, max_chars: int = 3000) -> str:
    return text if len(text) <= max_chars else text[:max_chars]


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError("Query and function embedding dimensions differ")
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb)
    return dot / denom if denom > 0 else 0.0


def rerank_with_embedding(description: str, funcs: list[dict], top_k: int = LLM_TOP_K) -> list[dict]:
    """Rank functions by cosine similarity between their embedding and the CVE description embedding.

    1 API call to embed the description, then N/batch_size calls for the functions.
    """
    if not funcs:
        return []

    # 1) Embed CVE description
    q_emb = embed_batch([description])[0]

    # 2) Embed function bodies in batches
    func_texts = [
        _truncate(f["body"] + "\n# docstring: " + (f.get("docstring") or ""))
        for f in funcs
    ]

    func_embs: list[list[float]] = []
    for start in tqdm(
        range(0, len(func_texts), EMBEDDING_BATCH_SIZE),
        desc="Embedding functions",
    ):
        batch = func_texts[start : start + EMBEDDING_BATCH_SIZE]
        func_embs.extend(embed_batch(batch))

    # 3) Cosine similarity
    scored = [
        {**f, "embedding_score": _cosine(q_emb, func_embs[i])}
        for i, f in enumerate(funcs)
    ]
    scored.sort(
        key=lambda x: (x["embedding_score"], x.get("bm25_score", 0.0)),
        reverse=True,
    )
    return scored[:top_k]
