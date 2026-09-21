import re
import hashlib
from tqdm import tqdm

from pyshare.evaluation.methods.vfarche.config import LLM_BATCH_SIZE, LLM_TOP_K
from pyshare.evaluation.methods.vfarche.llm.client import chat
from pyshare.evaluation.methods.vfarche.llm.prompts import BATCH_SYSTEM, PAIRWISE_SYSTEM, batch_user_prompt, pairwise_user_prompt


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


_PAIR_CACHE: dict[str, str] = {}


def _func_id(func: dict) -> str:
    return f"{func.get('qualname')}@{func.get('file')}:{func.get('start_line')}"


def _pair_key(description: str, a: dict, b: dict) -> str:
    left, right = sorted([_func_id(a), _func_id(b)])
    raw = f"{description}\n{left}\n{right}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _compare_pair(description: str, a: dict, b: dict) -> float:
    """Return 1 if a wins, 0 if b wins, 0.5 for tie."""
    reverse = _func_id(a) > _func_id(b)
    left, right = (b, a) if reverse else (a, b)
    key = _pair_key(description, a, b)
    if key not in _PAIR_CACHE:
        raw = chat(
            messages=[
                {"role": "system", "content": PAIRWISE_SYSTEM},
                {"role": "user", "content": pairwise_user_prompt(description, left, right)},
            ]
        )
        _PAIR_CACHE[key] = raw.strip().upper()
    ans = _PAIR_CACHE[key]
    if ans.startswith("A"):
        return 0.0 if reverse else 1.0
    if ans.startswith("B"):
        return 1.0 if reverse else 0.0
    return 0.5


def _swiss_pairs(order: list[int], played: set[tuple[int, int]]) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    pool = order[:]
    while len(pool) >= 2:
        a = pool.pop(0)
        match_at = None
        for idx, b in enumerate(pool):
            if tuple(sorted((a, b))) not in played:
                match_at = idx
                break
        if match_at is None:
            b = pool.pop(0)
        else:
            b = pool.pop(match_at)
        pairs.append((a, b))
    return pairs


def rerank_with_pairwise(
    description: str,
    funcs: list[dict],
    top_k: int = LLM_TOP_K,
    swiss_rounds: int = 8,
) -> list[dict]:
    """Paper-style hybrid ranking: Swiss tournament top-20, then exhaustive pairwise."""
    if not funcs:
        return []
    if len(funcs) == 1:
        return funcs[:1]

    _PAIR_CACHE.clear()  # cache belongs to this CVE/model run only

    scores = [0.0 for _ in funcs]
    played: set[tuple[int, int]] = set()

    rounds = min(swiss_rounds, max(1, len(funcs) - 1))
    for _ in tqdm(range(rounds), desc="Swiss pairwise rounds"):
        order = sorted(range(len(funcs)), key=lambda i: (scores[i], funcs[i].get("bm25_score", 0.0)), reverse=True)
        for i, j in _swiss_pairs(order, played):
            played.add(tuple(sorted((i, j))))
            result = _compare_pair(description, funcs[i], funcs[j])
            scores[i] += result
            scores[j] += 1.0 - result

    swiss_ranked = sorted(
        range(len(funcs)),
        key=lambda i: (scores[i], funcs[i].get("bm25_score", 0.0)),
        reverse=True,
    )
    finalist_idx = swiss_ranked[: min(top_k, len(swiss_ranked))]
    wins = {i: 0.0 for i in finalist_idx}

    pairs = [
        (finalist_idx[i], finalist_idx[j])
        for i in range(len(finalist_idx))
        for j in range(i + 1, len(finalist_idx))
    ]
    for i, j in tqdm(pairs, desc="Exhaustive pairwise finals"):
        result = _compare_pair(description, funcs[i], funcs[j])
        wins[i] += result
        wins[j] += 1.0 - result

    final = sorted(
        finalist_idx,
        key=lambda i: (wins[i], scores[i], funcs[i].get("bm25_score", 0.0)),
        reverse=True,
    )
    return [
        {
            **funcs[i],
            "swiss_score": scores[i],
            "pairwise_score": wins[i],
        }
        for i in final
    ]
