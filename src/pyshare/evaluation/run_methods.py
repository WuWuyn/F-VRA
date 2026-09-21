"""Auto-run driver — run each VF-localization method end-to-end on one dataset.

The driver only ORCHESTRATES: it picks the requested adapters and runs them one
after another. Each adapter (see adapters/) converts the master dataset to its own
input format, runs the method's native pipeline, and writes a normalized
prediction file to results/predictions/<method>.jsonl.

This script does NOT compute metrics — that is a separate later layer that reads
the prediction JSONL files (see evaluation/README.md, "Scope").

Usage (from repo root, or with PYTHONPATH including this dir):
    python -m pyshare.evaluation.run_methods --methods vfdetector vffinder
    python -m pyshare.evaluation.run_methods --master data/processed/cve_to_vf_evaluation.jsonl \
                                     --methods vfdetector \
                                     --python-bin C:/path/to/venv/python.exe

Per-method interpreter: methods live in different envs (vfdetector=venv,
vffinder=conda+LLM key). Use --python-bin to point at the right interpreter, or
run one method at a time from inside its activated env.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from pyshare.evaluation.paths import DEFAULT_MASTER, PROJECT_ROOT, RESULTS_ROOT

HERE = Path(__file__).resolve().parent

from pyshare.evaluation.adapters.vfdetector_adapter import VFDetectorAdapter
from pyshare.evaluation.adapters.vffinder_adapter import VFFinderAdapter
from pyshare.evaluation.adapters.vfarche_adapter import VFArcheAdapter
from pyshare.evaluation.adapters.base import RunContext

REGISTRY = {
    "vfdetector": VFDetectorAdapter(),
    "vffinder": VFFinderAdapter(),
    "vfarche": VFArcheAdapter(),
}

REPO_ROOT = PROJECT_ROOT
DEFAULT_OUT = RESULTS_ROOT / "predictions"


def normalize_results_path(path: Path) -> Path:
    """Keep evaluation artifacts under results/evaluation.

    Older commands sometimes passed evaluation/result/... by hand. Treat that
    as the same logical location and redirect writes to results/evaluation/...
    so fresh runs do not recreate the legacy singular folder.
    """
    return path


def run_selected(
    methods: list[str],
    master: Path,
    out_dir: Path,
    python_bin: str,
    limit: int | None = None,
    *,
    experiment_group: str = "main",
    variant: str | None = None,
    axis: str | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Run registered adapters with one normalized context per method."""
    out_dir = normalize_results_path(out_dir)
    done, failed, skipped = [], [], []
    for name in methods:
        adapter = REGISTRY.get(name)
        if adapter is None:
            logging.warning("Unknown method '%s' - not in registry, skipping.", name)
            skipped.append(name)
            continue
        if not getattr(adapter, "enabled", True):
            logging.warning("Method '%s' is disabled, skipping.", name)
            skipped.append(name)
            continue

        logging.info("==== Running %s ====", name)
        t0 = time.time()
        ctx = RunContext(
            master_path=master,
            out_dir=out_dir,
            python_bin=python_bin,
            limit=limit,
            experiment_group=experiment_group,
            variant=variant,
            axis=axis,
        )
        try:
            paths = adapter.run(ctx)
            logging.info(
                "Done %s in %.1fs -> %s",
                name,
                time.time() - t0,
                ", ".join(map(str, paths)),
            )
            done.append(name)
        except Exception as e:  # noqa: BLE001 - one method failing must not kill the rest
            logging.error("FAILED %s: %s  (continuing with next method)", name, e)
            failed.append(name)
    return done, failed, skipped


def main() -> None:
    ap = argparse.ArgumentParser(description="Run VF-localization methods end-to-end.")
    ap.add_argument("--master", type=Path, default=DEFAULT_MASTER,
                    help=f"Master benchmark JSONL (default: {DEFAULT_MASTER.name}).")
    ap.add_argument("--methods", nargs="+", default=["vfdetector", "vffinder", "vfarche"],
                    help="Which methods to run (order = run order).")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT,
                    help=f"Where to write <method>.jsonl (default: {DEFAULT_OUT}).")
    ap.add_argument("--python-bin", default=sys.executable,
                    help="Interpreter for the methods' subprocess calls.")
    ap.add_argument("--limit", "--sample-size", dest="limit", type=int, default=None,
                    help="Select the first N master benchmark records per method.")
    args = ap.parse_args()

    if not args.master.exists():
        sys.exit(f"ERROR: master dataset not found: {args.master}")
    args.out_dir = normalize_results_path(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s | %(levelname)s | %(message)s")

    done, failed, skipped = [], [], []
    for name in args.methods:
        adapter = REGISTRY.get(name)
        if adapter is None:
            logging.warning("Unknown method '%s' — not in registry, skipping.", name)
            skipped.append(name)
            continue
        if not getattr(adapter, "enabled", True):
            logging.warning("Method '%s' is disabled, skipping.", name)
            skipped.append(name)
            continue

        logging.info("==== Running %s ====", name)
        t0 = time.time()
        ctx = RunContext(
            master_path=args.master,
            out_dir=args.out_dir,
            python_bin=args.python_bin,
            limit=args.limit,
            experiment_group="main",
        )
        try:
            paths = adapter.run(ctx)
            logging.info("Done %s in %.1fs -> %s",
                         name, time.time() - t0, ", ".join(map(str, paths)))
            done.append(name)
        except Exception as e:  # noqa: BLE001 — one method failing must not kill the rest
            logging.error("FAILED %s: %s  (continuing with next method)", name, e)
            failed.append(name)

    logging.info("SUMMARY — done: %s | failed: %s | skipped: %s",
                 done or "—", failed or "—", skipped or "—")


if __name__ == "__main__":
    main()
