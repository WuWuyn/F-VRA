from __future__ import annotations

from pathlib import Path

from pyshare.core.config import settings
from pyshare.core.models import LocalizeResult
from pyshare.localization.bm25 import rank_bm25
from pyshare.localization.function_parser import parse_repo


def localize(
    cve_id: str,
    *,
    description: str = "",
    repo_path: str | Path | None = None,
    top_k: int = 20,
) -> LocalizeResult:
    """Locate candidate vulnerable functions using the vfloc-py Python pipeline.

    The old `pipeline/cve_localization` implementation was removed because it was
    a Java-era VFArCHE migration. This service is intentionally Python-first:
    parse Python functions, rank with BM25, optionally let callers layer LLM
    reranking later.
    """
    if not description or repo_path is None:
        return LocalizeResult(
            cve_id=cve_id,
            package="",
            vf="",
            mode="needs_context",
            candidates=[],
        )

    funcs = parse_repo(repo_path)
    ranked = rank_bm25(description, funcs, top_k=top_k or settings.llm_top_k)
    candidates = [item.get("qualname") or item["name"] for item in ranked]
    return LocalizeResult(
        cve_id=cve_id,
        package=Path(repo_path).name,
        vf=candidates[0] if candidates else "",
        score=float(ranked[0].get("bm25_score", 0.0)) if ranked else 0.0,
        mode="bm25",
        candidates=candidates,
    )
