"""Audit VFDetector function extraction coverage.

This script answers the evidence gap that predictions alone cannot answer:
whether the ground-truth vulnerable functions were present in the extracted
candidate function corpus before ranking.

It reports, per CVE:
  - Python files read from the vulnerable ref
  - files parsed by AST vs handled by regex fallback
  - extracted function count
  - strict and alias GT-in-corpus coverage

Fast path: run against the shared evaluation repo cache. Use --clone-missing
only if you intentionally want this script to fetch missing repos.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import time
from pathlib import Path

from pyshare.evaluation.paths import PROJECT_ROOT, RESULTS_ROOT

REPO_ROOT = PROJECT_ROOT
DEFAULT_REPO_CACHE = RESULTS_ROOT / "artifacts" / "repo_cache"

from pyshare.evaluation.adapters.vfdetector_adapter import to_vfdetector  # noqa: E402
from pyshare.evaluation.adapters.base import iter_master  # noqa: E402
from pyshare.evaluation.methods.vfdetector.core.code_processor import FunctionExtractor  # noqa: E402
from pyshare.evaluation.methods.vfdetector.runner import (  # noqa: E402
    choose_vuln_ref,
    ensure_repo_cloned,
    module_path,
    read_py_sources,
    slugify,
)


FIELDNAMES = [
    "cve_id",
    "repo",
    "ref_used",
    "py_files",
    "ast_files",
    "regex_fallback_files",
    "extracted_functions",
    "gt_count",
    "gt_strict_covered",
    "gt_alias_covered",
    "missing_gt_strict",
    "missing_gt_alias",
    "elapsed_secs",
    "error",
]


def _load_samples(master: Path, limit: int | None = None) -> list[dict]:
    samples = [r for r in (to_vfdetector(x) for x in iter_master(master)) if r]
    return samples[:limit] if limit else samples


def _candidate_forms(func_id: str) -> set[str]:
    if "::" not in func_id:
        return {func_id, func_id.split(".")[-1]}
    file_path, qualified = func_id.split("::", 1)
    full_qualified = f"{module_path(file_path)}.{qualified}"
    return {func_id, qualified, full_qualified, qualified.split(".")[-1]}


def _strict_forms(func_id: str) -> set[str]:
    if "::" not in func_id:
        return {func_id}
    file_path, qualified = func_id.split("::", 1)
    return {func_id, qualified, f"{module_path(file_path)}.{qualified}"}


def _extract_repo(
    dest: Path, ref: str, cache: dict[tuple[str, str], dict]
) -> dict:
    key = (str(dest.resolve()), ref)
    if key in cache:
        return cache[key]

    sources = read_py_sources(dest, ref)
    if sources is None:
        result = {"error": "ls_tree_failed"}
        cache[key] = result
        return result

    candidate_ids: list[str] = []
    py_files = ast_files = regex_fallback_files = 0
    for fp, source in sources.items():
        py_files += 1
        try:
            ast.parse(source)
            ast_files += 1
        except SyntaxError:
            regex_fallback_files += 1
        funcs = FunctionExtractor(source).extract()
        for fname in funcs:
            candidate_ids.append(f"{fp}::{fname}")

    strict_index: set[str] = set()
    alias_index: set[str] = set()
    for fid in candidate_ids:
        strict_index.update(_strict_forms(fid))
        alias_index.update(_candidate_forms(fid))

    result = {
        "error": "",
        "py_files": py_files,
        "ast_files": ast_files,
        "regex_fallback_files": regex_fallback_files,
        "extracted_functions": len(candidate_ids),
        "strict_index": strict_index,
        "alias_index": alias_index,
    }
    cache[key] = result
    return result


def _audit_sample(
    sample: dict,
    workspaces: Path,
    clone_missing: bool,
    extraction_cache: dict[tuple[str, str], dict],
) -> dict:
    start = time.time()
    repo_url = sample["repo_url"]
    slug = slugify(repo_url.replace("https://github.com/", ""))
    dest = workspaces / slug
    row = {
        "cve_id": sample["cve_id"],
        "repo": repo_url.replace("https://github.com/", ""),
        "ref_used": "",
        "py_files": 0,
        "ast_files": 0,
        "regex_fallback_files": 0,
        "extracted_functions": 0,
        "gt_count": len(sample.get("all_functions") or []),
        "gt_strict_covered": 0,
        "gt_alias_covered": 0,
        "missing_gt_strict": "",
        "missing_gt_alias": "",
        "elapsed_secs": 0.0,
        "error": "",
    }
    try:
        if not dest.exists():
            if not clone_missing:
                row["error"] = f"workspace_missing: {dest}"
                return row
            fetch_ref = (sample.get("vulnerable_ref") or "").strip() or sample["commit_sha"]
            err = ensure_repo_cloned(repo_url, fetch_ref, dest)
            if err:
                row["error"] = err
                return row

        ref, note = choose_vuln_ref(sample, dest)
        row["ref_used"] = ref
        if note:
            row["error"] = note

        extracted = _extract_repo(dest, ref, extraction_cache)
        if extracted.get("error"):
            row["error"] = extracted["error"]
            return row
        row["py_files"] = extracted["py_files"]
        row["ast_files"] = extracted["ast_files"]
        row["regex_fallback_files"] = extracted["regex_fallback_files"]
        row["extracted_functions"] = extracted["extracted_functions"]
        strict_index = extracted["strict_index"]
        alias_index = extracted["alias_index"]

        missing_strict: list[str] = []
        missing_alias: list[str] = []
        for gt in sample.get("all_functions") or []:
            if gt in strict_index:
                row["gt_strict_covered"] += 1
            else:
                missing_strict.append(gt)
            gt_aliases = {gt, gt.split("::", 1)[-1], gt.split(".")[-1]}
            if gt_aliases & alias_index:
                row["gt_alias_covered"] += 1
            else:
                missing_alias.append(gt)

        row["missing_gt_strict"] = "|".join(missing_strict)
        row["missing_gt_alias"] = "|".join(missing_alias)
        return row
    finally:
        row["elapsed_secs"] = round(time.time() - start, 2)


def _summary(rows: list[dict]) -> dict:
    n = len(rows)
    source_error_prefixes = ("workspace_missing", "clone_failed", "ls_tree_failed")
    audited = [
        r for r in rows
        if not str(r["error"]).startswith(source_error_prefixes)
    ]
    gt_total_all = sum(int(r["gt_count"]) for r in rows)
    gt_total = sum(int(r["gt_count"]) for r in audited)
    strict = sum(int(r["gt_strict_covered"]) for r in audited)
    alias = sum(int(r["gt_alias_covered"]) for r in audited)
    return {
        "rows": n,
        "audited_without_source_error": len(audited),
        "source_errors": n - len(audited),
        "py_files": sum(int(r["py_files"]) for r in audited),
        "ast_files": sum(int(r["ast_files"]) for r in audited),
        "regex_fallback_files": sum(int(r["regex_fallback_files"]) for r in audited),
        "extracted_functions": sum(int(r["extracted_functions"]) for r in audited),
        "gt_total_all_rows": gt_total_all,
        "gt_total_audited_rows": gt_total,
        "gt_strict_covered": strict,
        "gt_alias_covered": alias,
        "gt_strict_coverage": round(strict / gt_total, 4) if gt_total else None,
        "gt_alias_coverage": round(alias / gt_total, 4) if gt_total else None,
        "cves_with_strict_missing_gt": sum(1 for r in audited if r["missing_gt_strict"]),
        "cves_with_alias_missing_gt": sum(1 for r in audited if r["missing_gt_alias"]),
        "note": (
            "Coverage is computed only over audited rows. If audited_without_source_error is 0, "
            "the run did not access any source/workspace and coverage is not meaningful."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit VFDetector extraction counters and GT-in-corpus coverage.")
    ap.add_argument("--master", type=Path, default=REPO_ROOT / "data" / "processed" / "cve_to_vf_evaluation.jsonl")
    ap.add_argument("--workspaces", type=Path, default=DEFAULT_REPO_CACHE)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "vfdetector_extraction_audit.csv")
    ap.add_argument("--summary", type=Path, default=REPO_ROOT / "docs" / "vfdetector_extraction_audit_summary.json")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--clone-missing", action="store_true", help="Fetch missing workspaces instead of reporting them.")
    args = ap.parse_args()

    samples = _load_samples(args.master, args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    extraction_cache: dict[tuple[str, str], dict] = {}
    with args.out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        for sample in samples:
            row = _audit_sample(sample, args.workspaces, args.clone_missing, extraction_cache)
            rows.append(row)
            writer.writerow(row)
            fh.flush()

    summary = _summary(rows)
    args.summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Wrote: {args.out}")
    print(f"Wrote: {args.summary}")


if __name__ == "__main__":
    main()
