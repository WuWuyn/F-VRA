from __future__ import annotations

from pyshare_core.config import settings
from pyshare_server.localization.models import FunctionInfo, VulnerableFunctionCandidate


def _normalise(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    maximum = max(scores.values())
    if maximum <= 0:
        return {key: 0.0 for key in scores}
    return {key: value / maximum for key, value in scores.items()}


def _source_excerpt(source: str, max_chars: int = 1800) -> str:
    return source if len(source) <= max_chars else source[:max_chars] + "\n# ... truncated"


def _rerank_document(function: FunctionInfo, max_chars: int = 5000) -> str:
    text = (
        f"name: {function.qualname}\n"
        f"file: {function.file_path}\n"
        f"lines: {function.start_line}-{function.end_line}\n"
        f"docstring: {function.docstring}\n"
        f"source:\n{function.source}"
    )
    return text if len(text) <= max_chars else text[:max_chars] + "\n# ... truncated"


def _openrouter_rerank_scores(
    description: str,
    candidates: list[FunctionInfo],
    *,
    model: str,
) -> dict[str, float]:
    from pyshare_server.localization.providers.llm_client import rerank

    documents = [_rerank_document(function) for function in candidates]
    ranked = rerank(
        query=description,
        documents=documents,
        model=model,
        top_n=len(documents),
    )
    by_index = {index: score for index, score in ranked}
    return {
        function.identity: max(0.0, min(1.0, by_index.get(index, 0.0)))
        for index, function in enumerate(candidates)
    }


def _chat_llm_scores(description: str, candidates: list[FunctionInfo]) -> dict[str, float]:
    from pyshare_server.localization.ranking.llm_rerank import rerank_with_llm

    payload = [
        {
            "name": item.function_name,
            "qualname": item.qualname,
            "file": item.file_path,
            "start_line": item.start_line,
            "body": item.source,
            "_identity": item.identity,
        }
        for item in candidates
    ]
    ranked = rerank_with_llm(description, payload, top_k=len(payload))
    return {
        item["_identity"]: min(float(item.get("llm_score", 0.0)) / 10.0, 1.0)
        for item in ranked
    }


def rank_candidates(
    description: str,
    candidates: list[FunctionInfo],
    relevance_scores: dict[str, float],
    evidence: dict[str, set[str]],
    *,
    top_k: int,
    use_llm: bool,
    use_rerank: bool,
    rerank_model: str | None = None,
    pairwise_scores: dict[str, float] | None = None,
    rerank_metadata: dict[str, str | bool | None] | None = None,
) -> list[VulnerableFunctionCandidate]:
    relevance = _normalise(relevance_scores)
    reranked: dict[str, float] = {}
    rerank_status = "disabled"
    rerank_source = None
    active_rerank_model = rerank_model or settings.openrouter_rerank_model
    rerank_candidates = candidates[: min(30, len(candidates))]
    if use_rerank and active_rerank_model and settings.llm_api_key and rerank_candidates:
        try:
            reranked = _openrouter_rerank_scores(
                description,
                rerank_candidates,
                model=active_rerank_model,
            )
            rerank_status = "used"
            rerank_source = "openrouter_rerank"
        except RuntimeError as exc:
            rerank_status = f"fallback: {exc}"
    elif use_llm and settings.llm_api_key and rerank_candidates:
        reranked = _chat_llm_scores(description, rerank_candidates)
        rerank_status = "used"
        rerank_source = "openrouter_chat"
        active_rerank_model = settings.llm_model
    elif use_rerank and active_rerank_model and not settings.llm_api_key:
        rerank_status = "disabled: OPENROUTER_API_KEY is not set"

    if rerank_metadata is not None:
        rerank_metadata.update(
            {
                "used": bool(reranked),
                "status": rerank_status,
                "source": rerank_source,
                "model": active_rerank_model if reranked else active_rerank_model or None,
            }
        )

    scored: list[tuple[float, FunctionInfo, list[str]]] = []
    for function in candidates:
        items = sorted(evidence.get(function.identity, set()))
        patch_strength = 0.0
        for item in items:
            if "overlaps changed patch lines" in item:
                patch_strength += 0.45
            elif "configuration/global" in item:
                patch_strength += 0.35
            elif "changed invocation" in item:
                patch_strength += 0.30
            elif item.startswith(("calls patch-related", "called by patch-related")):
                patch_strength += 0.20
        patch_strength = min(patch_strength, 0.65)
        semantic = (
            pairwise_scores.get(function.identity, 0.0)
            if pairwise_scores is not None
            else reranked.get(function.identity, relevance.get(function.identity, 0.0))
        )
        score = min(1.0, patch_strength + (0.55 if patch_strength else 0.85) * semantic)
        scored.append((score, function, items))

    scored.sort(
        key=lambda item: (item[0], relevance.get(item[1].identity, 0.0)),
        reverse=True,
    )
    output: list[VulnerableFunctionCandidate] = []
    for rank, (score, function, items) in enumerate(scored[:top_k], 1):
        reasons = items or ["semantically relevant to the expanded CVE description"]
        output.append(
            VulnerableFunctionCandidate(
                rank=rank,
                score=round(score, 6),
                confidence=round(min(0.99, 0.35 + 0.64 * score), 6),
                function_name=function.function_name,
                qualname=function.qualname,
                file_path=function.file_path,
                start_line=function.start_line,
                end_line=function.end_line,
                source_excerpt=_source_excerpt(function.source),
                why_this_may_be_vulnerable="; ".join(reasons),
                evidence_used=reasons,
            )
        )
    return output
