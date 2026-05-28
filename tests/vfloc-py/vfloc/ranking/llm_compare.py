import re
from tqdm import tqdm

from config import LLM_BATCH_SIZE, LLM_TOP_K
from vfloc.llm.client import chat
from vfloc.llm.prompts import BATCH_SYSTEM, batch_user_prompt


_LINE = re.compile(r"^\s*(\d+)\s*,\s*(\d+(?:\.\d+)?)\s*$")


def _score_batch(description: str, funcs: list[dict]) -> dict[int, float]:
    raw = chat(
        messages=[
            {"role": "system", "content": BATCH_SYSTEM},
            {"role": "user", "content": batch_user_prompt(description, funcs)},
        ]
    )
    scores: dict[int, float] = {}
    for line in raw.splitlines():
        m = _LINE.match(line)
        if m:
            scores[int(m.group(1))] = float(m.group(2))
    return scores


def rerank_with_llm(description: str, funcs: list[dict], top_k: int = LLM_TOP_K) -> list[dict]:
    """Score every function in batches via gpt-4o-mini, return top_k sorted by score."""
    if not funcs:
        return []

    scored: list[dict] = []
    for start in tqdm(range(0, len(funcs), LLM_BATCH_SIZE), desc="LLM compare"):
        batch = funcs[start : start + LLM_BATCH_SIZE]
        batch_scores = _score_batch(description, batch)
        for i, f in enumerate(batch):
            scored.append({**f, "llm_score": batch_scores.get(i, 0.0)})

    scored.sort(key=lambda x: (x["llm_score"], x.get("bm25_score", 0.0)), reverse=True)
    return scored[:top_k]
