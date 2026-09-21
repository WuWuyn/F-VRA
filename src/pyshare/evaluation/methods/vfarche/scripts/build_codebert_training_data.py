from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from pyshare.evaluation.methods.vfarche.data.load_cve import load
from pyshare.evaluation.methods.vfarche.parser.python_parser import parse_repo
from pyshare.evaluation.methods.vfarche.parser.repo_cloner import clone_or_update
from pyshare.evaluation.methods.vfarche.retrieval.tracker import non_test_functions, select_with_tracker


def _func_key(func: dict) -> str:
    return f"{func.get('file')}::{func.get('qualname')}::{func.get('start_line')}"


def _record(cve: dict, func: dict, label: int, source: str) -> dict:
    return {
        "cve_id": cve["cve_id"],
        "description": cve["description"],
        "func_id": _func_key(func),
        "qualified_name": func.get("qualname"),
        "function_name": func.get("name"),
        "file_path": func.get("file"),
        "start_line": func.get("start_line"),
        "end_line": func.get("end_line"),
        "source": func.get("body") or "",
        "label": label,
        "label_source": source,
    }


def build_rows(
    dataset: str | Path,
    *,
    limit: int | None,
    tracker_top_k: int,
    negatives_per_positive: int,
    seed: int,
) -> list[dict]:
    rng = random.Random(seed)
    cves = load(dataset)
    if limit:
        cves = cves[:limit]

    rows: list[dict] = []
    for cve in cves:
        if not (cve.get("vulnerable_ref") and cve.get("fix_commit")):
            continue
        print(f"[build-codebert] {cve['cve_id']}")
        repo = clone_or_update(cve["repo_url"], cve.get("vulnerable_ref"))
        funcs = non_test_functions(parse_repo(repo))
        positives = select_with_tracker(repo, cve, funcs, top_k=tracker_top_k)
        if not positives:
            continue

        pos_keys = {_func_key(f) for f in positives}
        for func in positives:
            rows.append(_record(cve, func, 1, "tracker"))

        negatives = [f for f in funcs if _func_key(f) not in pos_keys]
        rng.shuffle(negatives)
        max_neg = min(len(negatives), len(positives) * negatives_per_positive)
        for func in negatives[:max_neg]:
            rows.append(_record(cve, func, 0, "non_tracker_sample"))

    rng.shuffle(rows)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Build CodeBERT cross-encoder training pairs from Tracker output.")
    ap.add_argument("--dataset", required=True, help="VFArCHE JSON/JSONL/CSV dataset.")
    ap.add_argument("--out", required=True, type=Path, help="Output JSONL training pairs.")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--tracker-top-k", type=int, default=100)
    ap.add_argument("--negatives-per-positive", type=int, default=4)
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    rows = build_rows(
        args.dataset,
        limit=args.limit,
        tracker_top_k=args.tracker_top_k,
        negatives_per_positive=args.negatives_per_positive,
        seed=args.seed,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[build-codebert] wrote {len(rows)} pairs -> {args.out}")


if __name__ == "__main__":
    main()
