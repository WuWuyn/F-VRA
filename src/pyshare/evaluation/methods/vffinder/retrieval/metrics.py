"""Small native metrics helper for VFFinder retrieval outputs.

The shared evaluation package computes the final cross-method metrics. This
module exists so ``python -m pyshare.evaluation.methods.vffinder.retrieval.retrieval`` can still report the
paper-style native retrieval metrics when a ground-truth JSON is supplied.
"""

from __future__ import annotations

from collections.abc import Iterable


DEFAULT_KS = (1, 5, 10)


def _ranked_id(item) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, (list, tuple)) and item:
        return str(item[0])
    if isinstance(item, dict):
        return str(
            item.get("func_id")
            or item.get("qualified_name")
            or item.get("function_name")
            or ""
        )
    return ""


def _aliases(func_id: str) -> set[str]:
    """Return tolerant aliases for native path::function identifiers.

    VFFinder's repo-wide corpus may rank ``path.py::Class.method`` while the
    legacy native ground-truth file often stores ``path.py::method``. Treat those
    as the same leaf function for native metrics; the shared evaluator remains
    the stricter source of final numbers.
    """
    if not func_id:
        return set()
    aliases = {func_id}
    if "::" in func_id:
        path, qual = func_id.split("::", 1)
        leaf = qual.split(".")[-1]
        aliases.add(qual)
        aliases.add(leaf)
        aliases.add(f"{path}::{leaf}")
    else:
        aliases.add(func_id.split(".")[-1])
    return aliases


def _truth_aliases(truth_items: Iterable) -> set[str]:
    out: set[str] = set()
    for item in truth_items or []:
        out.update(_aliases(_ranked_id(item)))
    return out


def _truth_alias_groups(truth_items: Iterable) -> list[set[str]]:
    return [aliases for item in (truth_items or [])
            if (aliases := _aliases(_ranked_id(item)))]


def _first_hit_rank(ranked_items: list, truth: set[str]) -> int:
    for idx, item in enumerate(ranked_items, start=1):
        if _aliases(_ranked_id(item)) & truth:
            return idx
    return 0


def evaluate(ranked: dict[str, list], ground_truth: dict[str, list],
             ks: tuple[int, ...] = DEFAULT_KS) -> dict[str, float]:
    """Compute MRR and Recall@K over native VFFinder ranked outputs."""
    if not ground_truth:
        return {"MRR": 0.0, **{f"Recall@{k}": 0.0 for k in ks}}

    reciprocal_sum = 0.0
    recall_sum = {k: 0.0 for k in ks}
    n = 0

    for cve_id, truth_items in ground_truth.items():
        truth_groups = _truth_alias_groups(truth_items)
        if not truth_groups:
            continue
        truth = set().union(*truth_groups)
        n += 1
        candidates = ranked.get(cve_id, [])
        first = _first_hit_rank(candidates, truth)
        if first:
            reciprocal_sum += 1.0 / first
        for k in ks:
            top_aliases: set[str] = set()
            for item in candidates[:k]:
                top_aliases.update(_aliases(_ranked_id(item)))
            hits = sum(1 for aliases in truth_groups if aliases & top_aliases)
            recall_sum[k] += hits / len(truth_groups)

    if n == 0:
        return {"MRR": 0.0, **{f"Recall@{k}": 0.0 for k in ks}}

    metrics = {"MRR": round(reciprocal_sum / n, 4)}
    for k in ks:
        metrics[f"Recall@{k}"] = round(recall_sum[k] / n, 4)
    return metrics
