"""audit_gt_coverage.py — does each CVE's ground truth actually live in the pool
it gets ranked against? This establishes the LEGITIMACY CEILING of the vffinder
results: a GT function that isn't in its CVE's per-library candidate pool can
NEVER be retrieved by any ranker, so its absence is a data/key/library bug — not
a model failure. Run this on the rebuilt corpus before trusting the metrics.

It reuses compute_metrics.match_tier (the EXACT matcher the metrics use), and
replicates retrieval.py's per-library subset selection (fe.library == tag, with
the same fallbacks), so "covered here" == "reachable by the real pipeline".

Reports:
  - coverage: % of CVEs whose GT is fully / partially / not present in its pool
  - the unwinnable CVEs (GT missing from pool) — the list to investigate
  - pool-size distribution (tiny pools make hit@k trivially easy — interpret with care)
  - library tags whose pool spans many top-level dirs (proxy for several repos
    collapsed under one coarse tag — a pool-mixing risk)

This is a fast in-memory set/index scan (no LLM, no network), so it is NOT
checkpointed — a re-run is cheap and idempotent.

CLI:
    python -m pyshare.evaluation.scripts.audit_gt_coverage
    python -m pyshare.evaluation.scripts.audit_gt_coverage --func-corpus PATH --ground-truth PATH --library-map PATH
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from pyshare.evaluation.metrics.compute_metrics import match_tier, _parse  # exact metric matcher

from pyshare.evaluation.methods.vffinder import config as vffinder_config  # noqa: E402


def _subset_libs(tag) -> list[str]:
    """Normalise a library_map value (str or list) to a list of tag names —
    mirrors retrieval.run_retrieval's lib_key handling."""
    if isinstance(tag, list):
        return tag
    return [tag]


def audit(func_corpus_path: Path, gt_path: Path, libmap_path: Path) -> int:
    funcs = json.loads(func_corpus_path.read_text(encoding="utf-8"))
    gt_map = {k: v for k, v in json.loads(gt_path.read_text(encoding="utf-8")).items()
              if not str(k).startswith("_")}
    libmap = {}
    if libmap_path.is_file():
        libmap = {k: v for k, v in json.loads(libmap_path.read_text(encoding="utf-8")).items()
                  if not str(k).startswith("_")}

    # Index corpus by library, then by bare function name → list of full func_ids.
    # match_tier requires the function name to match first, so indexing by name
    # turns the per-GT scan from O(pool) into O(funcs with that name).
    by_lib_name: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    by_lib_topdirs: dict[str, set[str]] = defaultdict(set)
    lib_func_count: Counter = Counter()
    all_by_name: dict[str, list[str]] = defaultdict(list)   # full-corpus fallback
    for fe in funcs:
        fid = fe["func_id"]
        lib = fe.get("library", "")
        _, name = _parse(fid)
        by_lib_name[lib][name].append(fid)
        all_by_name[name].append(fid)
        lib_func_count[lib] += 1
        path = fid.split("::", 1)[0]
        by_lib_topdirs[lib].add(path.split("/", 1)[0])

    def pool_for(cve_id: str):
        """Return (name_index, pool_size, label) replicating retrieval's subset
        selection: library tag → fe.library filter, else full corpus."""
        tag = libmap.get(cve_id)
        if not tag:
            return all_by_name, len(funcs), "full(no-tag)"
        libs = _subset_libs(tag)
        idx: dict[str, list[str]] = defaultdict(list)
        size = 0
        for lib in libs:
            for nm, fids in by_lib_name.get(lib, {}).items():
                idx[nm].extend(fids)
                size += len(fids)
        if size == 0:                       # retrieval falls back to full corpus
            return all_by_name, len(funcs), f"full(tag '{libs[0]}' empty)"
        return idx, size, libs[0]

    def gt_covered(gt_id: str, name_index: dict[str, list[str]]) -> bool:
        _, gn = _parse(gt_id)
        for cand_fid in name_index.get(gn, ()):
            if match_tier(cand_fid, gt_id) is not None:
                return True
        return False

    full_cov = part_cov = none_cov = no_gt = 0
    missing_rows: list[tuple] = []
    pool_sizes: list[int] = []
    fallback_full = 0

    for cve_id, gts in gt_map.items():
        gts = [g for g in gts if g and not str(g).startswith("_")]
        if not gts:
            no_gt += 1
            continue
        name_index, size, label = pool_for(cve_id)
        pool_sizes.append(size)
        if label.startswith("full"):
            fallback_full += 1
        hit = [g for g in gts if gt_covered(g, name_index)]
        if len(hit) == len(gts):
            full_cov += 1
        elif hit:
            part_cov += 1
            missing_rows.append((cve_id, label, size, [g for g in gts if g not in hit]))
        else:
            none_cov += 1
            missing_rows.append((cve_id, label, size, gts))

    n = full_cov + part_cov + none_cov
    print(f"\n=== GT coverage over {n} CVEs (corpus: {len(funcs)} functions) ===")
    print(f"  GT fully in pool   : {full_cov:4d}  ({100*full_cov/max(n,1):.1f}%)  <- recall ceiling = 100% reachable")
    print(f"  GT partially in pool: {part_cov:4d}  ({100*part_cov/max(n,1):.1f}%)")
    print(f"  GT NOT in pool      : {none_cov:4d}  ({100*none_cov/max(n,1):.1f}%)  <- UNWINNABLE: investigate ref/key/library")
    print(f"  (CVEs with empty GT, skipped: {no_gt})")
    print(f"  CVEs falling back to FULL corpus (no/empty tag): {fallback_full}")

    if pool_sizes:
        pool_sizes.sort()
        q = lambda p: pool_sizes[min(len(pool_sizes) - 1, int(p * len(pool_sizes)))]
        tiny = sum(1 for s in pool_sizes if s <= 50)
        print(f"\n=== Pool-size distribution (per-CVE candidate count) ===")
        print(f"  min={pool_sizes[0]}  p25={q(.25)}  median={q(.5)}  p75={q(.75)}  max={pool_sizes[-1]}")
        print(f"  pools <= 50 functions (hit@k trivially easy): {tiny}")

    multi = sorted(((lib, len(dirs), lib_func_count[lib])
                    for lib, dirs in by_lib_topdirs.items() if lib and len(dirs) > 1),
                   key=lambda x: -x[1])
    if multi:
        print(f"\n=== Library tags spanning >1 top-level dir (possible multi-repo pool mixing) ===")
        for lib, ndirs, nf in multi[:20]:
            print(f"  '{lib}': {ndirs} top-dirs, {nf} functions")

    if missing_rows:
        print(f"\n=== CVEs with GT missing from pool ({len(missing_rows)}) ===")
        for cve_id, label, size, miss in missing_rows[:60]:
            print(f"  {cve_id}  [pool={label}, size={size}]  missing: {miss}")
        if len(missing_rows) > 60:
            print(f"  ... and {len(missing_rows) - 60} more")

    return none_cov


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit whether GT lives in each CVE's pool.")
    ap.add_argument("--func-corpus", type=Path,
                    default=vffinder_config.OUTPUT_DIR / "function_corpus_all.json")
    ap.add_argument("--ground-truth", type=Path,
                    default=vffinder_config.DATA_DIR / "ground_truth_sample.json")
    ap.add_argument("--library-map", type=Path,
                    default=vffinder_config.DATA_DIR / "cve_library_map.json")
    args = ap.parse_args()
    for p in (args.func_corpus, args.ground_truth):
        if not p.is_file():
            raise SystemExit(f"not found: {p}")
    audit(args.func_corpus, args.ground_truth, args.library_map)


if __name__ == "__main__":
    main()
