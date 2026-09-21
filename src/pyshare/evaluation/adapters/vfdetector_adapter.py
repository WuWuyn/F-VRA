"""VF-Detector adapter — tVSM function ranking.

Pipeline (native): `python -m pyshare.evaluation.methods.vfdetector.runner` clones each repo at the parent of the fix
commit (vulnerable state) and ranks functions by tVSM lexical similarity. It
writes a native results CSV with, per CVE, the top-10 ranked function names+scores
and the ground-truth names. We parse that CSV into the common contract.

results.csv is an append-only CHECKPOINT LOG, not a table: under --resume the
native runner skips successful CVEs but re-runs failed ones, appending a fresh
row per retry (and duplicate input cve_ids within one run each get a row). So
the same cve_id can appear many times; readers must dedup keeping the LAST row
(the newest state) — exactly what the native `load_existing` does. `parse_results`
below applies the same rule before normalizing.

Input format it needs:
    cve_id, repo_url, commit_sha (FIX commit), vulnerable_ref, vf_file (.py),
    all_functions, description
"""
from __future__ import annotations

import csv
import os
from pathlib import Path

from .base import (
    MethodAdapter,
    REPO_ROOT,
    RunContext,
    iter_master,
    load_master_index,
    pred_record,
    run_step,
    write_jsonl,
)
from pyshare.evaluation.paths import ADAPTER_RESULTS_ROOT, METHODS_ROOT

VFDETECTOR = METHODS_ROOT / "vfdetector"
ADAPTER_DATA_DIR = ADAPTER_RESULTS_ROOT / "vfdetector"
INPUT_JSONL = ADAPTER_DATA_DIR / "from_master.jsonl"


def _module_path(rel_path: str) -> str:
    path = rel_path.replace("\\", "/").strip("/")
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".")


def _ground_truth_id(fn: dict) -> str:
    """Prefer the benchmark qualified_name; fall back to path/name when needed."""
    qualified = fn.get("qualified_name")
    if qualified:
        return qualified
    file_path = fn.get("file_path")
    name = fn.get("function_name")
    if file_path and name:
        return f"{file_path}::{name}"
    return name or ""


def to_vfdetector(rec: dict) -> dict | None:
    """master record -> vfdetector input record (or None if unusable)."""
    rcf = rec.get("root_cause_functions") or []
    python_rcf = [
        fn for fn in rcf
        if str(fn.get("file_path", "")).endswith(".py")
    ]
    if not python_rcf:
        return None
    fix = next((p["sha"] for p in rec.get("patches", [])
                if p.get("role") == "canonical_fix"), None)
    if not fix and rec.get("patches"):
        fix = rec["patches"][0].get("sha")
    if not (fix and rec.get("repo_url") and rec.get("description")):
        return None
    funcs = list(dict.fromkeys(
        fid for fn in python_rcf
        if (fid := _ground_truth_id(fn))
    ))
    if not funcs:
        return None
    return {
        "cve_id": rec.get("advisory_id"),
        "repo_url": rec["repo_url"],
        "commit_sha": fix,
        "vulnerable_ref": rec.get("vulnerable_ref") or "",
        "vf_file": python_rcf[0].get("file_path", ""),
        "all_functions": funcs,
        "description": rec["description"],
    }


def _ranked_item(func_id: str, score: float | None) -> dict:
    """Normalize native ids to the benchmark qualified_name convention."""
    file_path = None
    qualified = func_id
    if "::" in func_id:
        file_path, qualified = func_id.split("::", 1)
    function_name = qualified.split(".")[-1]

    benchmark_qualified = None
    normalized_id = func_id
    if file_path:
        module = _module_path(file_path)
        benchmark_qualified = (
            qualified
            if qualified == module or qualified.startswith(f"{module}.")
            else f"{module}.{qualified}"
        )
        normalized_id = benchmark_qualified

    return {
        "func_id": normalized_id,
        "qualified_name": benchmark_qualified,
        "file_path": file_path,
        "function_name": function_name,
        "score": score,
    }


def _parse_top10(cell: str) -> list[dict]:
    """'name:0.83|path.py::Cls.fn:0.41' -> normalized ranked entries."""
    out: list[dict] = []
    for chunk in (cell or "").split("|"):
        if not chunk:
            continue
        func_id, _, score = chunk.rpartition(":")
        try:
            out.append(_ranked_item(func_id or chunk, float(score)))
        except ValueError:
            out.append(_ranked_item(chunk, None))
    return out


def _float_or_none(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def parse_results(
    results_csv: Path,
    method: str = "vfdetector",
    *,
    variant: str = "default",
    experiment_group: str = "main",
    axis: str | None = None,
) -> list[dict]:
    """results.csv (append-only checkpoint log) -> ONE record per cve_id.

    Keeps the LAST row per cve_id: resume order guarantees a success row is never
    re-run, so the last row is a CVE's newest state (final retry outcome). A CVE
    whose last row is still a failure keeps an EMPTY ranking — the metric layer
    counts it as a miss and reports it under `n_empty`."""
    rows: dict[str, dict] = {}
    total = 0
    with results_csv.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            rows[row["cve_id"]] = row
            total += 1
    if total > len(rows):
        print(f"    [{method}] results.csv: {total} rows -> {len(rows)} unique CVEs "
              f"({total - len(rows)} stale retry rows ignored)")
    records = []
    for row in rows.values():
        ranked = _parse_top10(row.get("top10", ""))
        gt = [g for g in (row.get("truth_functions", "") or "").split("|") if g]
        records.append(
            pred_record(
                row["cve_id"],
                method,
                variant,
                ranked,
                gt,
                experiment_group=experiment_group,
                axis=axis,
                runtime_secs=_float_or_none(row.get("detect_secs")),
            )
        )
    return records


class VFDetectorAdapter(MethodAdapter):
    name = "vfdetector"
    enabled = True

    def run(self, ctx: RunContext) -> list[Path]:
        # 1) convert master -> vfdetector input
        recs = [r for r in (to_vfdetector(x) for x in iter_master(ctx.master_path)) if r]
        if ctx.limit:
            recs = recs[:ctx.limit]
        write_jsonl(INPUT_JSONL, recs)
        print(f"    [vfdetector] {len(recs)} records -> {INPUT_JSONL}")

        # 2) run native pipeline (clone @parent + tVSM rank). Each evaluation
        #    run gets its own CSV under ctx.out_dir so pilot runs cannot parse
        #    stale rows from a previous full run.
        ctx.out_dir.mkdir(parents=True, exist_ok=True)
        run_results = (ctx.out_dir / f"_{self.name}_results.csv").resolve()
        run_summary = (ctx.out_dir / f"_{self.name}_summary.json").resolve()
        run_failures = (ctx.out_dir / f"_{self.name}_failures.jsonl").resolve()
        workspaces = (ADAPTER_DATA_DIR / "workspaces").resolve()
        timeout_secs = int(os.environ.get("VFDETECTOR_TIMEOUT_SECS", str(7 * 24 * 3600)))
        run_step(
            ["python", "-m", "pyshare.evaluation.methods.vfdetector.runner",
             "--samples", str(INPUT_JSONL),
             "--results", str(run_results),
             "--summary", str(run_summary),
             "--failures", str(run_failures),
             "--workspaces", str(workspaces),
             "--resume"],
            cwd=REPO_ROOT, python_bin=ctx.python_bin, timeout=timeout_secs,
        )

        # 3) parse results.csv -> common contract (dedup retried CVEs, keep last)
        records = parse_results(
            run_results,
            self.name,
            variant=ctx.variant or "default",
            experiment_group=ctx.experiment_group,
            axis=ctx.axis,
        )
        meta = load_master_index(ctx.master_path)
        for rec in records:
            m = meta.get(rec["cve_id"], {})
            rec["group_id"] = m.get("group_id") or rec["group_id"]
            if m.get("ground_truth"):
                rec["ground_truth"] = m["ground_truth"]

        out_path = ctx.out_dir / f"{self.name}.jsonl"
        write_jsonl(out_path, records)
        print(f"    [vfdetector] {len(records)} predictions -> {out_path}")
        return [out_path]
