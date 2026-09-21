"""preprocess.py — build shared artifacts for every advisory group (doc §11).

For each group in the master benchmark:
  1. fetch_repo: clone + checkout `vulnerable_ref`            (fetch_repo.py)
  2. extract_functions: full function corpus at that ref      (extract_functions.py)
     -> artifacts/function_corpus/<group_slug>.jsonl   (= repository_functions scope)

The function corpus is the shared candidate pool that every method ranks over,
and the join key (qualified_name) for matching predictions to ground truth.

Patch-based scopes (changed_commit / patch_extended) and modified_functions are
added in a later pass (need patch diffs); this pass covers the repository scope,
which needs only `vulnerable_ref`.

A per-group manifest records status + the ground-truth qualified_names and
whether each was found in the extracted corpus (a critical QA gate: if a GT VF is
missing from the corpus, no method can ever rank it).

CLI:
    python -m pyshare.evaluation.scripts.preprocess
    python -m pyshare.evaluation.scripts.preprocess --limit 5
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from pyshare.evaluation.paths import DEFAULT_MASTER, PROJECT_ROOT, RESULTS_ROOT

from .extract_functions import extract_corpus
from .fetch_repo import ensure_repo_at_ref, slugify

HERE = Path(__file__).resolve().parent
EVAL_ROOT = HERE.parent
REPO_ROOT = PROJECT_ROOT
ARTIFACTS = RESULTS_ROOT / "artifacts"
CORPUS_DIR = ARTIFACTS / "function_corpus"
CACHE_DIR = ARTIFACTS / "repo_cache"
MANIFEST = ARTIFACTS / "preprocess_manifest.jsonl"


def gt_qualified_names(group: dict) -> list[str]:
    return [f["qualified_name"] for f in (group.get("root_cause_functions") or [])
            if f.get("qualified_name")]


def process_group(group: dict) -> dict:
    """Fetch + extract one group. Never raises — returns a manifest row."""
    gid = group.get("group_id") or group.get("advisory_id") or "unknown"
    slug = slugify(gid)
    repo_url = group.get("repo_url")
    ref = group.get("vulnerable_ref")
    row = {"group_id": gid, "slug": slug, "repo_url": repo_url, "ref": ref,
           "status": "ok", "error": "", "n_functions": 0,
           "gt": gt_qualified_names(group), "gt_found": [], "gt_missing": []}

    if not (repo_url and ref):
        row["status"] = "skipped"
        row["error"] = "missing repo_url or vulnerable_ref"
        return row

    dest = CACHE_DIR / slugify(repo_url.replace("https://github.com/", ""))
    err = ensure_repo_at_ref(repo_url, ref, dest)
    if err:
        row["status"] = "error"
        row["error"] = err
        return row

    corpus = extract_corpus(dest)
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    out = CORPUS_DIR / f"{slug}.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for rec in corpus:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    names = {r["qualified_name"] for r in corpus}
    row["n_functions"] = len(corpus)
    row["gt_found"] = [g for g in row["gt"] if g in names]
    row["gt_missing"] = [g for g in row["gt"] if g not in names]
    return row


def main() -> None:
    ap = argparse.ArgumentParser(description="Build shared function-corpus artifacts.")
    ap.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    ap.add_argument("--limit", type=int, default=None,
                    help="Only the first N groups (smoke test).")
    args = ap.parse_args()

    groups = [json.loads(l) for l in args.master.open(encoding="utf-8") if l.strip()]
    if args.limit:
        groups = groups[:args.limit]

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    rows = []
    with MANIFEST.open("w", encoding="utf-8") as mf:
        for i, g in enumerate(groups, 1):
            row = process_group(g)
            rows.append(row)
            mf.write(json.dumps(row, ensure_ascii=False) + "\n")
            mf.flush()
            tag = row["status"].upper()
            extra = (f"{row['n_functions']} fns, gt_found {len(row['gt_found'])}/{len(row['gt'])}"
                     if row["status"] == "ok" else row["error"][:80])
            print(f"[{i}/{len(groups)}] {tag} {row['group_id']}  {extra}")

    ok = [r for r in rows if r["status"] == "ok"]
    miss = sum(len(r["gt_missing"]) for r in ok)
    total_gt = sum(len(r["gt"]) for r in ok)
    print(f"\nSUMMARY: {len(ok)}/{len(rows)} groups ok | "
          f"GT coverage in corpus: {total_gt - miss}/{total_gt} "
          f"({miss} missing) | manifest -> {MANIFEST}")


if __name__ == "__main__":
    main()
