"""Run repository-level evaluation smoke checks with plain Python.

This script validates the empirical-study structure, method registry, manifest,
and standalone check scripts. It does not run full method pipelines.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from pyshare.evaluation.paths import CONFIG_ROOT, METHODS_ROOT, PACKAGE_ROOT, PROJECT_ROOT, RESULTS_ROOT

EVAL_ROOT = PACKAGE_ROOT
REPO_ROOT = PROJECT_ROOT


def _ok(message: str) -> None:
    print(f"PASS {message}")


def _require(path: Path, kind: str = "path") -> None:
    if not path.exists():
        raise AssertionError(f"Missing {kind}: {path}")
    _ok(f"{kind} exists: {path.relative_to(REPO_ROOT)}")


def _run(args: list[str], cwd: Path = REPO_ROOT) -> None:
    subprocess.run(args, cwd=cwd, check=True)
    _ok(" ".join(args))


def _run_module(module: str, *args: str, cwd: Path = REPO_ROOT) -> None:
    _run([sys.executable, "-m", module, *args], cwd=cwd)


def _vfdetector_nltk_ready() -> bool:
    try:
        import nltk
    except ImportError:
        return False
    resources = (
        "tokenizers/punkt",
        "tokenizers/punkt_tab",
        "corpora/stopwords",
        "corpora/wordnet.zip",
        "taggers/averaged_perceptron_tagger_eng",
    )
    try:
        for resource in resources:
            nltk.data.find(resource)
    except LookupError:
        return False
    return True


def check_structure() -> None:
    for path in [
        EVAL_ROOT / "run_methods.py",
        EVAL_ROOT / "run_ablation.py",
        CONFIG_ROOT / "methods.manifest.json",
        EVAL_ROOT / "adapters",
        EVAL_ROOT / "metrics",
        EVAL_ROOT / "scripts",
        RESULTS_ROOT / "predictions",
        RESULTS_ROOT / "ablation",
        RESULTS_ROOT / "metrics",
        RESULTS_ROOT / "stats",
        METHODS_ROOT / "vfdetector",
        METHODS_ROOT / "vffinder",
        METHODS_ROOT / "vfarche",
    ]:
        _require(path, "directory" if path.is_dir() else "file")


def check_manifest() -> None:
    data = json.loads((CONFIG_ROOT / "methods.manifest.json").read_text(encoding="utf-8"))
    methods = {item["method_id"] for item in data.get("methods", [])}
    expected = {"vfdetector", "vffinder", "vfarche"}
    if not expected <= methods:
        raise AssertionError(f"Manifest methods missing: {sorted(expected - methods)}")
    _ok("method manifest includes all three methods")


def check_registry() -> None:
    from pyshare.evaluation import run_methods

    expected = {"vfdetector", "vffinder", "vfarche"}
    actual = set(run_methods.REGISTRY)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise AssertionError(f"Registry missing methods: {sorted(missing)}")
    if extra:
        raise AssertionError(f"Registry has unexpected methods: {sorted(extra)}")
    _ok("run_methods registry includes canonical methods only")


def main() -> int:
    check_structure()
    check_manifest()
    check_registry()
    _run_module("pyshare.evaluation.metrics.check_metrics")
    _run_module("pyshare.evaluation.scripts.check_run_ablation")
    _run_module("pyshare.evaluation.scripts.check_vfdetector_ranker")
    nltk_ready = _vfdetector_nltk_ready()
    if nltk_ready:
        _run_module("pyshare.evaluation.scripts.check_vfdetector_code_processor")
    else:
        print("SKIP vfdetector code-processor check (NLTK data missing; run doctor)")
    _run_module("pyshare.evaluation.scripts.check_vfdetector_adapter")
    _run_module("pyshare.evaluation.scripts.check_vfarche_tracker")
    _run_module("pyshare.evaluation.scripts.check_vfarche_runtime")
    if nltk_ready:
        _run_module("pyshare.evaluation.scripts.check_vffinder_fidelity")
    else:
        print("SKIP vffinder fidelity check (NLTK data missing; run doctor)")
    _run_module("pyshare.evaluation.run_methods", "--methods", "vfarche", "--limit", "0", "--help")
    _run_module("pyshare.evaluation.run_ablation", "--list")
    _run_module("pyshare.evaluation.cli", "list")
    _run_module("pyshare.evaluation.cli", "list", "--ablation")
    if nltk_ready:
        _run_module("pyshare.evaluation.methods.vfdetector.runner", "--help")
    else:
        print("SKIP vfdetector runner import (NLTK data missing; run doctor)")
    if nltk_ready:
        _run_module("pyshare.evaluation.methods.vffinder.scripts.prepare_webapp_data", "--help")
    else:
        print("SKIP vffinder command import (NLTK data missing; run doctor)")
    _run_module("pyshare.evaluation.methods.vfarche.cli", "--help")
    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
