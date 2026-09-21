"""Prepare VFFinder data files from a native VFFinder JSONL dataset.

This script *only* converts the JSONL dataset into the three input files the
rest of the pipeline expects under config.DATA_DIR. It does NOT build the
function corpus - that is Phase 3 and lives in
`build_function_corpus_from_jsonl.py`.

Outputs:
    config.DATA_DIR/cve_descriptions.json      {cve_id: {description, role, vendor_product_version}}
    config.DATA_DIR/ground_truth_sample.json   {cve_id: [vulnerable_func_names]}
    config.DATA_DIR/cve_library_map.json       {cve_id: library_prefix}

Role split:
    - Default (no `--eval-limit`): ALL CVEs -> role="eval". This is the paper's
      leave-one-out setup (Section 5.2: "we remove the ground truth corresponding
      to the query description from the case pool") - every CVE is scored, and the
      case pool is built with `rebuild_case_pool.py --include-all`, where the
      retriever excludes the query CVE by id so a CVE never demonstrates itself.
      The number of inputs is therefore the dataset size, not a hardcoded count.
    - With `--eval-limit N`: only the first/sampled N CVEs -> role="eval",
      remaining CVEs (capped by `--casepool-limit`) -> role="casepool". Use this
      only if you deliberately want a fixed held-out demonstration pool.
    - With `--seed`, eval CVEs are random.sample'd reproducibly instead of
      taken in file order.

Usage (from the directory containing vffinder/):
    python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data                       # all CVEs = eval
    python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data --jsonl path/to/file.jsonl
    python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data --eval-limit 20       # fixed 20-CVE eval
    python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data --eval-limit 20 --seed 42
    python -m pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data --eval-limit 20 --casepool-limit 50

Then build the function corpus (Phase 3):
    python -m pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl
"""

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path


from pyshare.evaluation.methods.vffinder import config

DEFAULT_JSONL = config.DATA_DIR / "from_master.jsonl"


# --- Helpers ------------------------------------------------------------------

def _extract_func_name(source: str) -> str:
    """Try to extract the function name from source using regex."""
    m = re.search(r"(?:async\s+)?def\s+(\w+)\s*\(", source)
    return m.group(1) if m else "unknown"


def _library_tag_from_package(packages: list[dict]) -> str:
    """Return a library identifier from the packages field.

    Heuristic: lowercase, then take the last hyphen/underscore component -
    works for "matrix-synapse" -> "synapse", "apache-airflow" -> "airflow".
    Imperfect for compound names like "djangorestframework", but the
    library_map is only a coarse filter for per-library retrieval.
    """
    if not packages:
        return ""
    name = packages[0].get("name", "").lower()
    for sep in ("-", "_"):
        parts = name.split(sep)
        if len(parts) > 1:
            name = parts[-1]
            break
    return name


def _vendor_product_version_terms(records: list[dict]) -> list[str]:
    """Best-effort VPV token list for description-corpus filtering.

    The author pipeline removes vendor/product/version terms from the AV/RC
    entity bag. Our Python benchmark does not carry CPVD's VPV field directly,
    so preserve the closest available package metadata when preparing
    cve_descriptions.json.
    """
    values: list[str] = []
    for rec in records:
        for pkg in rec.get("packages") or []:
            for key in ("name", "version", "ecosystem"):
                if pkg.get(key):
                    values.append(str(pkg[key]))
        for key in ("package_name", "repo_url"):
            if rec.get(key):
                values.append(str(rec[key]))

    terms: set[str] = set()
    for value in values:
        for part in re.findall(r"[A-Za-z]+|\d+(?:\.\d+)*", value):
            part = part.lower()
            if len(part) > 1:
                terms.add(part)
    return sorted(terms)


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  WARNING: line {lineno} skipped ({e})", file=sys.stderr)
    return records


# --- Main preparation logic ---------------------------------------------------

# --- Ground-truth normalization -----------------------------------

def _function_id_from_meta(fn: dict, vf_file: str) -> str:
    """Return the strongest identifier available for one vulnerable function."""
    qualified = str(fn.get("qualified_name") or fn.get("qualname") or "").strip()
    file_path = str(fn.get("file_path") or vf_file or "").strip()
    name = str(fn.get("function_name") or fn.get("name") or "").strip()
    if qualified:
        return f"{file_path}::{qualified}" if file_path else qualified
    if file_path and name:
        return f"{file_path}::{name}"
    return name


def _ground_truth_functions(rec: dict) -> list[str]:
    """Prefer full root_cause_functions when present; fall back to all_functions."""
    vf_file = str(rec.get("vf_file", "") or "").strip()
    rcf = rec.get("root_cause_functions") or []
    funcs: list[str] = []
    if isinstance(rcf, list) and rcf:
        for fn in rcf:
            if isinstance(fn, dict):
                fid = _function_id_from_meta(fn, vf_file)
                if fid:
                    funcs.append(fid)
    else:
        for fn_name in rec.get("all_functions") or []:
            fn_name = str(fn_name).strip()
            if not fn_name:
                continue
            funcs.append(f"{vf_file}::{fn_name}" if vf_file else fn_name)
    return list(dict.fromkeys(funcs))

def prepare(jsonl_path: Path,
            eval_limit: int | None = None,
            casepool_limit: int | None = None,
            seed: int | None = None) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Reading {jsonl_path} ...")
    records = load_jsonl(jsonl_path)
    print(f"  {len(records)} records loaded")

    # Group records by cve_id (preserve insertion order).
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        cve_id = rec.get("cve_id", "")
        if cve_id:
            by_cve[cve_id].append(rec)

    all_cve_ids = list(by_cve.keys())
    print(f"  {len(all_cve_ids)} unique CVE IDs")

    # -- Eval / casepool split ------------------------------------------------
    # eval_limit is None  -> leave-one-out: ALL CVEs are eval, no held-out pool.
    #                        (Pair with rebuild_case_pool.py --include-all.)
    # eval_limit is an int -> fixed split: first/sampled N are eval, rest casepool.
    if eval_limit is None:
        eval_cves_list = list(all_cve_ids)
        casepool_pool = []
        split_mode = "leave-one-out (all CVEs are eval)"
    elif seed is not None:
        rng = random.Random(seed)
        shuffled = list(all_cve_ids)
        rng.shuffle(shuffled)
        eval_cves_list = shuffled[:eval_limit]
        casepool_pool = shuffled[eval_limit:]
        split_mode = f"random.sample(seed={seed})"
    else:
        eval_cves_list = all_cve_ids[:eval_limit]
        casepool_pool = all_cve_ids[eval_limit:]
        split_mode = "first N by JSONL order"

    if casepool_limit is not None:
        casepool_pool = casepool_pool[:casepool_limit]

    eval_cves = set(eval_cves_list)
    casepool_cves = set(casepool_pool)
    print(f"  split mode: {split_mode}")
    print(f"  eval={len(eval_cves)}, casepool={len(casepool_cves)}")

    # The set we actually write out (eval union casepool). CVEs outside this set
    # are dropped from cve_descriptions / ground_truth / library_map.
    kept = eval_cves | casepool_cves

    # -- 1. cve_descriptions.json ---------------------------------------------
    descriptions: dict[str, dict] = {}
    for cve_id, recs in by_cve.items():
        if cve_id not in kept:
            continue
        desc = recs[0].get("description", "")
        role = "eval" if cve_id in eval_cves else "casepool"
        descriptions[cve_id] = {
            "description": desc,
            "role": role,
            "vendor_product_version": _vendor_product_version_terms(recs),
        }

    desc_out = config.DATA_DIR / "cve_descriptions.json"
    with open(desc_out, "w", encoding="utf-8") as f:
        json.dump(descriptions, f, indent=2, ensure_ascii=False)
    print(f"\n[1/3] cve_descriptions.json -> {desc_out}  ({len(descriptions)} entries)")

    # -- 2. ground_truth_sample.json ------------------------------------------
    # Prefer root_cause_functions when available; fall back to all_functions.
    # Keep the strongest function identifiers available in the dataset.
    # Older JSONL datasets fall back to all_functions-based ids.
    ground_truth: dict[str, list[str]] = {}
    for cve_id, recs in by_cve.items():
        if cve_id not in kept:
            continue
        gt_funcs: set[str] = set()
        for rec in recs:
            gt_funcs.update(_ground_truth_functions(rec))
        ground_truth[cve_id] = sorted(gt_funcs)

    gt_out = config.DATA_DIR / "ground_truth_sample.json"
    with open(gt_out, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)
    print(f"[2/3] ground_truth_sample.json -> {gt_out}  ({len(ground_truth)} entries)")

    # -- 3. cve_library_map.json ----------------------------------------------
    library_map: dict[str, str] = {}
    for cve_id, recs in by_cve.items():
        if cve_id not in kept:
            continue
        pkgs = recs[0].get("packages") or []
        tag = _library_tag_from_package(pkgs)
        if tag:
            library_map[cve_id] = tag

    libmap_out = config.DATA_DIR / "cve_library_map.json"
    with open(libmap_out, "w", encoding="utf-8") as f:
        json.dump(library_map, f, indent=2, ensure_ascii=False)
    print(f"[3/3] cve_library_map.json   -> {libmap_out}  ({len(library_map)} entries)")

    # -- Summary --------------------------------------------------------------
    print("\n=== Data preparation complete ===")
    print(f"  Eval CVEs    : {len(eval_cves)}")
    print(f"  Casepool CVEs: {len(casepool_cves)}")
    print(f"  Split mode   : {split_mode}")
    print(f"\nNext steps:")
    print(f"  python -m pyshare.evaluation.methods.vffinder.scripts.build_function_corpus_from_jsonl")
    print(f"  python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level direct --eval-only")
    print(f"  python -m pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl --level direct --extras-only")


# --- CLI ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert a native VFFinder JSONL dataset to pipeline inputs "
                    "(cve_descriptions, ground_truth_sample, cve_library_map)."
    )
    parser.add_argument("--jsonl", default=str(DEFAULT_JSONL),
                        help=f"Path to the JSONL dataset (default: {DEFAULT_JSONL})")
    parser.add_argument("--eval-limit", type=int, default=None,
                        help="Number of CVEs assigned to eval role. Omit (default) "
                             "for leave-one-out: ALL CVEs become eval and the case "
                             "pool is built with rebuild_case_pool.py --include-all.")
    parser.add_argument("--casepool-limit", type=int, default=None,
                        help="Cap casepool size (default: all remaining CVEs). "
                             "Use this to control LLM cost.")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for eval/casepool split. "
                             "When omitted, the first N CVEs by JSONL order "
                             "are eval (legacy behaviour).")
    args = parser.parse_args()

    jsonl_path = Path(args.jsonl)
    if not jsonl_path.exists():
        print(f"ERROR: JSONL file not found: {jsonl_path}", file=sys.stderr)
        sys.exit(1)

    prepare(
        jsonl_path,
        eval_limit=args.eval_limit,
        casepool_limit=args.casepool_limit,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
