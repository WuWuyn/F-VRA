"""VFFinder adapter — ICL extraction + priority semantic retrieval.

Native pipeline is 8 steps (run from `methods/`, with the VFFinder dependencies
and LLM key in the repository-root `.env`). Steps 3 & 5 call the LLM; everything else is local. It
produces three ranked-function files (one per ICL level):
    results/evaluation/adapters/vffinder/native_output/retrieval_results_all.json   -> variant "direct"
    results/evaluation/adapters/vffinder/native_output/retrieval_results_sicl.json  -> variant "s-icl"
    results/evaluation/adapters/vffinder/native_output/retrieval_results_picl.json  -> variant "p-icl"
each shaped {"ranked": {cve_id: [[func_id, score], ...]}}.

The adapter builds a repo-wide function corpus from the benchmark's vulnerable
refs before retrieval, so VFFinder ranks against real project-level distractors
instead of the old ground-truth-only fallback corpus.
"""
from __future__ import annotations

import json
import os
import re
import time
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


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


SHARED_ENV_FILE = REPO_ROOT / ".env"


def _configured_output_dir() -> Path:
    env_values = _read_env(SHARED_ENV_FILE)
    raw = os.getenv("VFFINDER_OUTPUT_DIR") or env_values.get("VFFINDER_OUTPUT_DIR")
    if raw:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = REPO_ROOT / path
        return path.resolve()
    return ADAPTER_RESULTS_ROOT / "vffinder" / "native_output"


def _configured_data_dir() -> Path:
    env_values = _read_env(SHARED_ENV_FILE)
    raw = os.getenv("VFFINDER_DATA_DIR") or env_values.get("VFFINDER_DATA_DIR")
    if raw:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = REPO_ROOT / path
        return path.resolve()
    return ADAPTER_RESULTS_ROOT / "vffinder"


VFFINDER = METHODS_ROOT / "vffinder"
DATA_DIR = _configured_data_dir()
INPUT_JSONL = DATA_DIR / "from_master.jsonl"
# master subset (same CVEs as INPUT_JSONL) driving the repo-wide corpus build
CORPUS_MASTER_SUBSET = DATA_DIR / "_corpus_master_subset.jsonl"
OUT = _configured_output_dir()
GT_PATH = DATA_DIR / "ground_truth_sample.json"
# class-priority hints (paper §4.4) — retrieval auto-loads data/class_hints.json
CLASS_HINTS_PATH = DATA_DIR / "class_hints.json"

# Class names mentioned in a CVE description (paper §4.1 regex extraction). Kept
# in the adapter so it needs no heavy vffinder imports in the harness env.
_CLASS_PATTERNS = [
    re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]+)"),
    re.compile(r"\b([A-Z][A-Za-z0-9_]+)\s+class\b"),
    re.compile(r"\b([A-Z][A-Za-z0-9_]+)\.[A-Za-z_][A-Za-z0-9_]*\s*\("),
]
_PASCAL_CASE = re.compile(r"\b[A-Z][a-zA-Z0-9]*[a-z][a-zA-Z0-9]*\b")
_DOTTED_PATH = re.compile(r"\b[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+\b")
_PY_FILE = re.compile(r"\b([A-Za-z_][\w]*)\.py\b")


def class_hints_for(description: str) -> list[str]:
    if not description:
        return []
    hits: list[str] = []

    def add(token: str) -> None:
        token = (token or "").strip()
        if len(token) >= 3 and token not in hits:
            hits.append(token)

    for pat in _CLASS_PATTERNS:
        for m in pat.findall(description):
            add(m)
    for m in _PASCAL_CASE.findall(description):
        add(m)
    for dotted in _DOTTED_PATH.findall(description):
        add(dotted)
        for part in dotted.split("."):
            add(part)
    for m in _PY_FILE.findall(description):
        add(m)
    return hits


VARIANTS = [
    ("direct", "description_corpus.json",       "retrieval_results_all.json"),
    ("s-icl",  "description_corpus_s_icl.json",  "retrieval_results_sicl.json"),
    ("p-icl",  "description_corpus_p_icl.json",  "retrieval_results_picl.json"),
]
ICL_VARIANTS = {variant for variant, _desc, _out in VARIANTS}


def _load_json_if_exists(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_function_corpus_counters() -> dict | None:
    counters = _load_json_if_exists(
        OUT / "function_corpus_all.json.component_counters.json"
    )
    if counters is not None:
        counters["counter_source"] = "final"
        return counters
    progress = _load_json_if_exists(OUT / "function_corpus_all.json.progress.json")
    if isinstance(progress, dict) and progress.get("component_counters"):
        counters = progress["component_counters"]
        counters["counter_source"] = "progress"
        counters["incomplete_checkpoint"] = True
        return counters
    return None


def _write_component_fire_counters(
    *,
    master_count: int,
    input_count: int,
    hints: dict[str, list[str]],
) -> Path:
    """Collect VFFinder component evidence emitted by native steps."""
    by_variant: dict[str, dict] = {}
    for variant, desc_corpus, out_file in VARIANTS:
        by_variant[variant] = {
            "description_preprocessing": _load_json_if_exists(
                OUT / f"{Path(desc_corpus).stem}_counters.json"
            ),
            "retrieval": _load_json_if_exists(
                OUT / f"{out_file}.component_counters.json"
            ),
        }
    payload = {
        "method": "vffinder",
        "master_rows_selected": master_count,
        "native_input_records": input_count,
        "class_hints": {
            "cves_total": len(hints),
            "cves_with_hints": sum(1 for values in hints.values() if values),
            "hints_total": sum(len(values) for values in hints.values()),
        },
        "function_corpus": _load_function_corpus_counters(),
        "function_corpus_smoke": _load_json_if_exists(
            OUT / "function_corpus_smoke.json.component_counters.json"
        ),
        "phase1": {
            "direct": _load_json_if_exists(OUT / "direct_phase1_counters.json"),
            "s-icl": _load_json_if_exists(OUT / "s_icl_phase1_counters.json"),
            "p-icl": _load_json_if_exists(OUT / "p_icl_phase1_counters.json"),
        },
        "variants": by_variant,
    }
    out = OUT / "component_fire_counters.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

def _has_llm_key() -> bool:
    placeholders = {"", "your-api-key-here", "changeme", "todo"}
    env_values = _read_env(SHARED_ENV_FILE)
    for key in ("OPENROUTER_API_KEY", "VFFINDER_API_KEY"):
        value = (os.getenv(key) or env_values.get(key, "")).strip()
        if value and value.lower() not in placeholders:
            return True
    return False


def to_vffinder(rec: dict) -> dict | None:
    """master record -> vffinder input record (or None if unusable)."""
    rcf = rec.get("root_cause_functions") or []
    if not rcf:
        return None
    funcs = [f["function_name"] for f in rcf if f.get("function_name")]
    if not (funcs and rec.get("description")):
        return None
    return {
        "cve_id": rec.get("advisory_id"),
        "description": rec["description"],
        "vf_file": rcf[0].get("file_path", ""),
        "all_functions": funcs,                 # primary VF first
        "root_cause_functions": rcf,            # preserve full labels for prep
        "vf_function": "",                      # no source in master (README §9)
        "packages": [{"name": rec.get("package_name", "")}],
    }


def _retrieval_cmd(desc_corpus: str, out_file: str, *, no_checkpoint: bool = False) -> list[str]:
    cmd = ["python", "-m", "pyshare.evaluation.methods.vffinder.retrieval.retrieval",
           "--desc-corpus", str(OUT / desc_corpus),
           "--func-corpus", str(OUT / "function_corpus_all.json"),
           "--output", str(OUT / out_file), "--top-k", "10"]
    embed_model = os.environ.get("VFF_EMBED_MODEL") or os.environ.get("VFFINDER_EMBED_MODEL")
    if embed_model:
        cmd += ["--model", embed_model]
    # Optional extension: VFF_RANK_STRATEGY=pairwise turns on an LLM tournament
    # re-rank. Default pointwise keeps paper Algorithm 1 only.
    strat = os.environ.get("VFF_RANK_STRATEGY")
    if strat:
        cmd += ["--rank-strategy", strat]
    if no_checkpoint:
        cmd += ["--no-checkpoint"]
    return cmd


def _fid(pair):
    if isinstance(pair, dict):
        return pair.get("func_id", "")
    if isinstance(pair, (list, tuple)):
        return pair[0]
    return str(pair)


def _score(pair):
    if isinstance(pair, dict):
        return pair.get("score")
    if isinstance(pair, (list, tuple)) and len(pair) > 1:
        return pair[1]
    return None


def _module_path(rel_path: str) -> str:
    path = rel_path.replace("\\", "/").strip("/")
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".")


def _ranked_item(func_id: str, score: float | None) -> dict:
    """Normalize VFFinder's file.py::Class.fn ids to benchmark qualified names."""
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


class VFFinderAdapter(MethodAdapter):
    name = "vffinder"
    enabled = True

    def run(self, ctx: RunContext) -> list[Path]:
        if not _has_llm_key():
            raise RuntimeError(
                "vffinder waiting for key: set OPENROUTER_API_KEY or "
                "VFFINDER_API_KEY in the repository-root .env before running "
                "the full LLM Phase-1 pipeline."
            )

        # 1) convert master -> vffinder input, pairing each source master record
        #    so the repo-wide corpus is built over EXACTLY the same CVEs (no
        #    --limit boundary mismatch between input and corpus).
        usable = [(m, v) for m in iter_master(ctx.master_path)
                  if (v := to_vffinder(m)) is not None]
        if ctx.limit:
            usable = usable[:ctx.limit]
        recs = [v for _m, v in usable]
        write_jsonl(INPUT_JSONL, recs)
        write_jsonl(CORPUS_MASTER_SUBSET, [m for m, _v in usable])
        # class-priority hints per CVE (paper §4.4) — retrieval auto-loads this.
        hints = {v["cve_id"]: class_hints_for(m.get("description", ""))
                 for m, v in usable}
        CLASS_HINTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        CLASS_HINTS_PATH.write_text(json.dumps(hints, ensure_ascii=False, indent=2),
                                    encoding="utf-8")
        n_hinted = sum(1 for h in hints.values() if h)
        print(f"    [vffinder] {len(recs)} records -> {INPUT_JSONL} "
              f"({n_hinted}/{len(hints)} CVEs have class hints)")
        jsonl = str(INPUT_JSONL)

        pipeline_t0 = time.time()

        # 2) repo-wide candidate corpus (clone @ vulnerable_ref + AST-extract EVERY
        #    function) — fixes the degenerate GT-only corpus (D-0005). Run from
        #    REPO_ROOT as the evaluation.scripts package; writes the same
        #    function_corpus_all.json the retrieval step consumes. The old
        #    build_function_corpus_from_jsonl step is intentionally removed.
        #    function-representation diagnostic via env: VFF_CHANNELS
        #    (entity channels to keep) and VFF_INLINE=0 (drop callee-inline calls).
        corpus_cmd = ["python", "-m", "pyshare.evaluation.scripts.build_vffinder_corpus",
                      "--master", str(CORPUS_MASTER_SUBSET),
                      "--out", str(OUT / "function_corpus_all.json")]
        if os.environ.get("VFF_CHANNELS"):
            corpus_cmd += ["--channels", os.environ["VFF_CHANNELS"]]
        if os.environ.get("VFF_INLINE") == "0":
            corpus_cmd += ["--no-inline"]
        run_step(corpus_cmd, cwd=REPO_ROOT, python_bin=ctx.python_bin, timeout=24 * 3600)

        # 3) run the native ICL pipeline (LLM steps auto-skip already-done CVEs)
        steps = [
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data", "--jsonl", jsonl],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl", "--level", "direct", "--all"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.rebuild_case_pool", "--include-all"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl", "--level", "s-icl", "--eval-only"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.run_phase1_icl", "--level", "p-icl", "--eval-only"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_direct"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_icl", "--level", "s-icl"],
            ["python", "-m", "pyshare.evaluation.methods.vffinder.scripts.rebuild_corpus_icl", "--level", "p-icl"],
        ]
        for cmd in steps:
            run_step(cmd, cwd=REPO_ROOT, python_bin=ctx.python_bin, timeout=24 * 3600)
        shared_secs = time.time() - pipeline_t0

        retrieval_secs: dict[str, float] = {}
        for variant, desc_corpus, out_file in VARIANTS:
            t0 = time.time()
            run_step(_retrieval_cmd(desc_corpus, out_file, no_checkpoint=bool(ctx.axis)),
                     cwd=REPO_ROOT, python_bin=ctx.python_bin, timeout=6 * 3600)
            retrieval_secs[variant] = time.time() - t0

        counters_path = _write_component_fire_counters(
            master_count=len(usable),
            input_count=len(recs),
            hints=hints,
        )
        print(f"    [vffinder] component fire counters -> {counters_path}")

        # 3) parse the 3 retrieval files -> common contract (one file, 3 variants)
        gt_map = json.loads(GT_PATH.read_text(encoding="utf-8"))
        meta = load_master_index(ctx.master_path)
        icl_filter = ctx.variant if ctx.variant in ICL_VARIANTS and not ctx.axis else None
        ablation_prefix = ctx.variant if ctx.axis and ctx.variant else None
        records = []
        for variant, _desc, out_file in VARIANTS:
            if icl_filter and icl_filter != variant:
                continue
            raw = json.loads((OUT / out_file).read_text(encoding="utf-8"))
            ranked_by_cve = raw.get("ranked", raw)
            n_variant_cves = len([cid for cid in ranked_by_cve if not str(cid).startswith("_")])
            output_variant = f"{ablation_prefix}:{variant}" if ablation_prefix else variant
            runtime_secs = (
                (shared_secs + retrieval_secs.get(variant, 0.0)) / max(1, n_variant_cves)
                if n_variant_cves
                else None
            )
            for cve_id, pairs in ranked_by_cve.items():
                if cve_id.startswith("_"):
                    continue
                ranked = [_ranked_item(_fid(p), _score(p)) for p in pairs]
                m = meta.get(cve_id, {})
                gt = m.get("ground_truth") or [
                    g for g in gt_map.get(cve_id, []) if not str(g).startswith("_")
                ]
                records.append(
                    pred_record(
                        cve_id,
                        self.name,
                        output_variant,
                        ranked,
                        gt,
                        group_id=m.get("group_id"),
                        experiment_group=ctx.experiment_group,
                        axis=ctx.axis,
                        runtime_secs=runtime_secs,
                    )
                )

        if recs and not records:
            error_files = [
                str((OUT / f"{out_file}.errors.json").resolve())
                for _variant, _desc, out_file in VARIANTS
                if (OUT / f"{out_file}.errors.json").is_file()
            ]
            details = "; ".join(error_files) if error_files else "no retrieval error files found"
            raise RuntimeError(
                "vffinder produced zero prediction records; retrieval likely failed. "
                f"Details: {details}"
            )

        out_path = ctx.out_dir / f"{self.name}.jsonl"
        write_jsonl(out_path, records)
        print(f"    [vffinder] {len(records)} predictions ({len(VARIANTS)} variants) -> {out_path}")
        return [out_path]
