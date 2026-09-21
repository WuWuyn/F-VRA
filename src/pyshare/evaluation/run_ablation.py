"""Run config-ablation sweeps through the shared evaluation harness.

Each sweep runs the same method under several environment-controlled variants,
stores one prediction file per variant, then invokes the common metrics and
stats layers on the collected prediction directory.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from pyshare.evaluation.paths import DEFAULT_MASTER, PROJECT_ROOT, RESULTS_ROOT

try:
    from tqdm import tqdm
except ImportError:  # degrade gracefully if tqdm is not installed
    tqdm = None

HERE = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT
ABLATION_ROOT = RESULTS_ROOT / "ablation"

from pyshare.evaluation.adapters.base import RunContext
from pyshare.evaluation.run_methods import REGISTRY


# (method, axis) -> ordered list of {variant, env}. Env vars are applied on top
# of a clean slate of the ablation-controlled vars for each variant run.
AXES: dict[tuple[str, str], list[dict]] = {
    ("vfarche", "rerank_strategy"): [
        {"variant": "bm25", "env": {}},
        {"variant": "chat", "env": {"VFARCHE_RERANK": "chat"}},
        {"variant": "embedding", "env": {"VFARCHE_RERANK": "embedding"}},
        {"variant": "pairwise", "env": {"VFARCHE_RERANK": "pairwise"}},
    ],
    ("vfarche", "description_expansion"): [
        {"variant": "no-expand", "env": {}},
        {"variant": "expand", "env": {"VFARCHE_EXPAND": "1"}},
    ],
    ("vfdetector", "synonym_expansion"): [
        {"variant": "no-expand", "env": {"VFDET_EXPAND": "0"}},
        {"variant": "expand", "env": {}},
    ],
    # The VFFinder adapter emits nested variants for these axes, e.g.
    # sig:direct, sig:s-icl, sig:p-icl.
    ("vffinder", "function_representation"): [
        {
            "variant": "sig",
            "env": {
                "VFF_CHANNELS": "APIName,APIClz,APIParaName,APIParaType",
                "VFF_INLINE": "0",
            },
        },
        {"variant": "sig+body", "env": {"VFF_INLINE": "0"}},
        {"variant": "sig+body+calls", "env": {}},
    ],
    # Pointwise is the paper Algorithm 1 path; pairwise is an LLM reranking
    # diagnostic extension.
    ("vffinder", "llm_ranking"): [
        {"variant": "pointwise", "env": {}},
        {"variant": "pairwise", "env": {"VFF_RANK_STRATEGY": "pairwise"}},
    ],
    ("vffinder", "anchor_recognition"): [
        {"variant": "regex", "env": {"VFFINDER_ANCHOR_MODE": "regex"}},
        {"variant": "ner+regex", "env": {"VFFINDER_ANCHOR_MODE": "ner_regex"}},
        {"variant": "llm+regex", "env": {"VFFINDER_ANCHOR_MODE": "llm_regex"}},
    ],
    ("vfarche", "candidate_selection"): [
        {"variant": "tracker", "env": {"VFARCHE_SELECTION": "tracker"}},
        {"variant": "bm25-fallback", "env": {"VFARCHE_SELECTION": "bm25"}},
    ],
}

CONTROLLED = (
    "VFARCHE_RERANK",
    "VFARCHE_EXPAND",
    "VFARCHE_SELECTION",
    "VFARCHE_CODEBERT_CHECKPOINT",
    "VFDET_EXPAND",
    "VFF_CHANNELS",
    "VFF_INLINE",
    "VFF_RANK_STRATEGY",
    "VFFINDER_ANCHOR_MODE",
)

NATIVE_ABLATIONS = {
    "vffinder / ICL level": (
        "direct vs s-icl vs p-icl are emitted by one normal "
        "`run_methods.py --methods vffinder` run."
    ),
    "any method / multi-VF treatment": (
        "Hit@k vs Recall@k vs AllVF@k are metric columns; no extra run needed."
    ),
}


def _apply_env(env: dict[str, str]) -> None:
    for key in CONTROLLED:
        os.environ.pop(key, None)
    os.environ.update(env)


def run_axis(
    method: str,
    axis: str,
    master: Path,
    python_bin: str,
    limit: int | None,
    out_root: Path = ABLATION_ROOT,
) -> Path:
    variants = AXES[(method, axis)]
    adapter = REGISTRY[method]
    out_dir = out_root / f"{method}__{axis}"
    out_dir.mkdir(parents=True, exist_ok=True)

    done: list[str] = []
    failed: list[str] = []
    progress_bar = (
        tqdm(variants, desc=f"ablation {method}/{axis}", unit="variant")
        if tqdm
        else None
    )
    progress_iter = progress_bar if progress_bar is not None else variants
    emit = tqdm.write if tqdm else print

    try:
        for cfg in progress_iter:
            label = cfg["variant"]
            print(f"\n==== ablation {method}/{axis} :: {label} ====")
            _apply_env(cfg["env"])
            ctx = RunContext(
                master_path=master,
                out_dir=out_dir,
                python_bin=python_bin,
                limit=limit,
                experiment_group="paper_ablation",
                variant=label,
                axis=axis,
            )
            try:
                adapter.run(ctx)
                src = out_dir / f"{method}.jsonl"
                dst = out_dir / f"{method}__{label}.jsonl"
                if src.exists():
                    src.replace(dst)
                    done.append(label)
                else:
                    failed.append(label)
            except Exception as exc:  # noqa: BLE001 - keep the sweep moving
                emit(f"  FAILED variant '{label}': {exc}")
                failed.append(label)
    finally:
        if progress_bar is not None:
            progress_bar.close()
        for key in CONTROLLED:
            os.environ.pop(key, None)

    print(f"\nSweep done: ok={done or '-'} failed={failed or '-'} -> {out_dir}")
    return out_dir


def run_metrics(pred_dir: Path, master: Path) -> None:
    print("\n========== ABLATION METRICS ==========")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pyshare.evaluation.metrics.compute_metrics",
            "--pred-dir",
            str(pred_dir),
            "--master",
            str(master),
            "--out",
            str(pred_dir / "metrics_summary.csv"),
            "--strat-out",
            str(pred_dir / "metrics_by_mapping.csv"),
        ],
        env={"PYTHONUTF8": "1", **os.environ},
        check=False,
    )
    print("\n========== SIGNIFICANCE (rr) ==========")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pyshare.evaluation.metrics.stats_tests",
            "--pred-dir",
            str(pred_dir),
            "--metric",
            "rr",
        ],
        env={"PYTHONUTF8": "1", **os.environ},
        check=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a config-ablation sweep for one method."
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--method")
    parser.add_argument("--axis")
    parser.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--limit", "--sample-size", dest="limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.list or not (args.method and args.axis):
        print("Available ablation sweeps (method / axis -> variants):")
        for (method, axis), variants in sorted(AXES.items()):
            labels = [cfg["variant"] for cfg in variants]
            print(f"  {method} / {axis}: {labels}")
        print("\nNative ablations (no sweep needed):")
        for title, how in NATIVE_ABLATIONS.items():
            print(f"  {title}\n    {how}")
        if not args.list:
            print("\nPass --method and --axis to run one.")
        return

    key = (args.method, args.axis)
    if key not in AXES:
        raise SystemExit(f"Unknown sweep {key}. Use --list to see options.")

    if args.dry_run:
        print(f"DRY RUN - {args.method}/{args.axis}:")
        for cfg in AXES[key]:
            print(
                f"  variant={cfg['variant']:16s} env={cfg['env']} "
                f"group=paper_ablation axis={args.axis}"
            )
        return

    out_dir = run_axis(args.method, args.axis, args.master, args.python_bin, args.limit)
    run_metrics(out_dir, args.master)


if __name__ == "__main__":
    main()
