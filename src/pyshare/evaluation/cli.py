"""Unified command line for running and checking the evaluation framework."""
from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from urllib.parse import urlparse
from pathlib import Path
from pyshare.evaluation.paths import CONFIG_ROOT, DEFAULT_MASTER, PROJECT_ROOT, RESULTS_ROOT


HERE = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT
DEFAULT_PRED_DIR = RESULTS_ROOT / "predictions"
DEFAULT_ABLATION_ROOT = RESULTS_ROOT / "ablation"
METHOD_MANIFEST = CONFIG_ROOT / "methods.manifest.json"


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


def cmd_smoke(_args: argparse.Namespace) -> int:
    from pyshare.evaluation.scripts import smoke_check

    return smoke_check.main()


def cmd_prepare_data(args: argparse.Namespace) -> int:
    from pyshare.evaluation.scripts.build_pyshare_master import build_master

    return build_master(args.benchmark, args.severity, args.output)


def cmd_list(args: argparse.Namespace) -> int:
    from pyshare.evaluation.run_ablation import AXES
    from pyshare.evaluation.run_methods import REGISTRY

    manifest = json.loads(METHOD_MANIFEST.read_text(encoding="utf-8"))
    methods = manifest.get("methods", [])

    if not args.ablation:
        print("Methods:")
        for item in methods:
            method_id = item["method_id"]
            adapter = REGISTRY.get(method_id)
            enabled = bool(adapter and getattr(adapter, "enabled", True))
            print(
                f"  {method_id}: paper={item.get('paper')} "
                f"status={item.get('status')} enabled={enabled}"
            )
            for variant in item.get("variants", []):
                print(
                    f"    - {variant['variant']}: group={variant.get('experiment_group')} "
                    f"status={variant.get('status')} "
                    f"paper_faithful={variant.get('paper_faithful')}"
                )

    print("Ablation axes:")
    for (method, axis), variants in sorted(AXES.items()):
        labels = [v["variant"] for v in variants]
        print(f"  {method} / {axis}: {labels}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from pyshare.evaluation.run_methods import normalize_results_path, run_selected

    _configure_logging()
    if not args.master.exists():
        raise SystemExit(f"ERROR: master dataset not found: {args.master}")
    args.out_dir = normalize_results_path(args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    done, failed, skipped = run_selected(
        args.methods,
        args.master,
        args.out_dir,
        args.python_bin,
        args.limit,
        experiment_group="main",
    )

    logging.info("SUMMARY - done: %s | failed: %s | skipped: %s",
                 done or "-", failed or "-", skipped or "-")
    return 1 if failed else 0


def _default_metric_outputs(pred_dir: Path) -> tuple[Path, Path]:
    if pred_dir.resolve() == DEFAULT_PRED_DIR.resolve():
        return (RESULTS_ROOT / "metrics" / "metrics_summary.csv",
                RESULTS_ROOT / "metrics" / "metrics_by_mapping.csv")
    return pred_dir / "metrics_summary.csv", pred_dir / "metrics_by_mapping.csv"


def cmd_metrics(args: argparse.Namespace) -> int:
    from pyshare.evaluation.metrics.compute_metrics import run_metrics
    from pyshare.evaluation.run_methods import normalize_results_path

    args.pred_dir = normalize_results_path(args.pred_dir)
    out, strat_out = _default_metric_outputs(args.pred_dir)
    if args.out:
        out = args.out
    if args.strat_out:
        strat_out = args.strat_out
    run_metrics(args.pred_dir, args.master, args.ks, out, strat_out)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    from pyshare.evaluation.metrics.stats_tests import run_stats
    from pyshare.evaluation.run_methods import normalize_results_path

    args.pred_dir = normalize_results_path(args.pred_dir)
    run_stats(args.pred_dir, args.metric, args.ks, args.alpha)
    return 0


def cmd_ablation(args: argparse.Namespace) -> int:
    from pyshare.evaluation.run_ablation import AXES, run_axis
    from pyshare.evaluation.run_methods import normalize_results_path

    args.out_root = normalize_results_path(args.out_root)
    key = (args.method, args.axis)
    if key not in AXES:
        known = ", ".join(f"{m}/{axis}" for m, axis in sorted(AXES))
        raise SystemExit(f"Unknown ablation {args.method}/{args.axis}. Known: {known}")
    if args.dry_run:
        print(f"DRY RUN - {args.method}/{args.axis}:")
        for cfg in AXES[key]:
            print(
                f"  variant={cfg['variant']:12s} env={cfg['env']} "
                f"group=paper_ablation axis={args.axis}"
            )
        return 0
    run_axis(args.method, args.axis, args.master, args.python_bin, args.limit, args.out_root)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from pyshare.evaluation.validate import print_validation, validate_predictions
    from pyshare.evaluation.run_methods import normalize_results_path

    args.pred_dir = normalize_results_path(args.pred_dir)
    summary = validate_predictions(args.pred_dir, args.master)
    print_validation(summary)
    return 1 if summary["errors"] else 0


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _has_real_value(values: dict[str, str], *keys: str) -> bool:
    placeholders = {"", "your-api-key-here", "changeme", "todo"}
    for key in keys:
        value = values.get(key, "").strip()
        if value and value.lower() not in placeholders:
            return True
    return False


def _mongo_reachable(uri: str, timeout: float = 2.0) -> bool:
    parsed = urlparse(uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 27017
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check method environment readiness without running the full pipelines."""
    methods = set(args.methods or ["vfdetector", "vffinder", "vfarche"])
    failures: list[str] = []

    env_path = REPO_ROOT / ".env"
    env = _read_env_file(env_path)

    if "vfdetector" in methods:
        try:
            import nltk
            resources = [
                ("punkt", "tokenizers/punkt"),
                ("stopwords", "corpora/stopwords"),
                ("wordnet", "corpora/wordnet.zip"),
            ]
            missing = []
            for label, path in resources:
                try:
                    nltk.data.find(path)
                except LookupError:
                    missing.append(label)
            if missing:
                print(f"vfdetector: missing NLTK data {missing}")
                failures.append("vfdetector: missing NLTK data")
            else:
                print("vfdetector: dependency nltk and data available")
        except Exception:
            print("vfdetector: missing dependency nltk")
            failures.append("vfdetector: missing dependency")

    if "vffinder" in methods:
        try:
            import nltk
            resources = [
                ("punkt_tab", "tokenizers/punkt_tab"),
                ("averaged_perceptron_tagger_eng", "taggers/averaged_perceptron_tagger_eng"),
                ("wordnet", "corpora/wordnet.zip"),
                ("stopwords", "corpora/stopwords"),
            ]
            missing = []
            for label, path in resources:
                try:
                    nltk.data.find(path)
                except LookupError:
                    missing.append(label)
            if missing:
                print(f"vffinder: missing NLTK data {missing}")
                failures.append("vffinder: missing NLTK data")
            else:
                print("vffinder: dependency nltk and data available")
        except Exception:
            print("vffinder: missing dependency nltk")
            failures.append("vffinder: missing dependency")

        if not env_path.exists():
            print(f"vffinder: missing .env at {env_path}")
            failures.append("vffinder: missing env")
        elif _has_real_value(env, "OPENROUTER_API_KEY", "VFFINDER_API_KEY"):
            print("vffinder: LLM key present")
        else:
            print("vffinder: waiting for key (OPENROUTER_API_KEY or VFFINDER_API_KEY)")
            failures.append("vffinder: waiting for key")

    if "vfarche" in methods:
        if not env_path.exists():
            print(f"vfarche: missing .env at {env_path}")
            failures.append("vfarche: missing env")
        else:
            provider = env.get("LLM_PROVIDER", "openrouter")
            print(f"vfarche: LLM_PROVIDER={provider}")
            if _has_real_value(env, "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
                print("vfarche: LLM key present")
            else:
                print("vfarche: waiting for key for LLM rerank variants")
                failures.append("vfarche: waiting for key")
            mongo_uri = env.get("MONGO_URI", "mongodb://localhost:27017")
            if _mongo_reachable(mongo_uri):
                print(f"vfarche: MongoDB reachable at {mongo_uri}")
            else:
                print(f"vfarche: MongoDB unavailable at {mongo_uri}")
                failures.append("vfarche: MongoDB unavailable")

    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pyshare eval")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("smoke", help="Run non-LLM repository smoke checks.")
    p.set_defaults(func=cmd_smoke)

    p = sub.add_parser("prepare-data", help="Build the evaluation master from PyShare data.")
    from pyshare.evaluation.scripts.build_pyshare_master import (
        DEFAULT_BENCHMARK,
        DEFAULT_OUTPUT,
        DEFAULT_SEVERITY,
    )
    p.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    p.add_argument("--severity", type=Path, default=DEFAULT_SEVERITY)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.set_defaults(func=cmd_prepare_data)

    p = sub.add_parser("list", help="List methods, experiments, and ablation axes.")
    p.add_argument("--ablation", action="store_true", help="Only show ablation axes.")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("run", help="Run one or more main methods.")
    p.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    p.add_argument("--methods", nargs="+", default=["vfdetector", "vffinder", "vfarche"])
    p.add_argument("--out-dir", type=Path, default=DEFAULT_PRED_DIR)
    p.add_argument("--python-bin", default=sys.executable)
    p.add_argument(
        "--limit",
        "--sample-size",
        dest="limit",
        type=int,
        default=None,
        help="Select the first N master benchmark records for every requested method.",
    )
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("metrics", help="Compute metrics for any prediction directory.")
    p.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    p.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    p.add_argument("--ks", type=int, nargs="+", default=[1, 5, 10])
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--strat-out", type=Path, default=None)
    p.set_defaults(func=cmd_metrics)

    p = sub.add_parser("stats", help="Run paired significance tests for any prediction directory.")
    p.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    p.add_argument("--metric", default="rr")
    p.add_argument("--ks", type=int, nargs="+", default=[1, 5, 10])
    p.add_argument("--alpha", type=float, default=0.05)
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("ablation", help="Run a method/config ablation axis.")
    p.add_argument("--method", required=True)
    p.add_argument("--axis", required=True)
    p.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    p.add_argument("--python-bin", default=sys.executable)
    p.add_argument(
        "--limit",
        "--sample-size",
        dest="limit",
        type=int,
        default=None,
        help="Select the first N master benchmark records for each ablation variant.",
    )
    p.add_argument("--out-root", type=Path, default=DEFAULT_ABLATION_ROOT)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_ablation)

    p = sub.add_parser("validate", help="Validate normalized prediction files.")
    p.add_argument("--pred-dir", type=Path, default=DEFAULT_PRED_DIR)
    p.add_argument("--master", type=Path, default=DEFAULT_MASTER)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("doctor", help="Check method dependencies, env files, keys, and services.")
    p.add_argument("--methods", nargs="+", default=None)
    p.set_defaults(func=cmd_doctor)

    return ap


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
