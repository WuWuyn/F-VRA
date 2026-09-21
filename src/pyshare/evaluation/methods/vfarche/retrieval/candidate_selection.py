from __future__ import annotations

from pathlib import Path

from pyshare.evaluation.methods.vfarche.ranking.bm25_rank import rank_bm25
from .codebert_selector import MissingCodeBERTCheckpoint, select_with_codebert
from .tracker import non_test_functions, select_with_tracker


def select_candidates(
    *,
    cve: dict,
    repo_path: str | Path,
    funcs: list[dict],
    description: str,
    mode: str = "auto",
    top_k: int = 100,
    codebert_checkpoint: str | Path | None = None,
) -> tuple[list[dict], str]:
    """Route candidate selection through Tracker, CodeBERT, or BM25 fallback."""
    mode = (mode or "auto").lower()
    has_patch = bool(cve.get("fix_commit") and (cve.get("vulnerable_ref") or cve.get("patch_commit")))

    if mode in {"auto", "tracker"} and has_patch:
        tracked = select_with_tracker(repo_path, cve, funcs, top_k=top_k)
        if tracked:
            return tracked, "tracker"
        if mode == "tracker":
            return [], "tracker-empty"

    if mode == "codebert" or (mode == "auto" and not has_patch):
        try:
            selected = select_with_codebert(
                description,
                non_test_functions(funcs),
                checkpoint=codebert_checkpoint,
                top_k=top_k,
            )
            return selected, "codebert"
        except MissingCodeBERTCheckpoint:
            if mode == "codebert":
                raise

    # Diagnostic fallback keeps the pipeline runnable for incomplete data while
    # the selector label records that this is not paper-faithful selection.
    return rank_bm25(description, non_test_functions(funcs), top_k=top_k), "bm25-fallback"
