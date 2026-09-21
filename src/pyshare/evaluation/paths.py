"""Canonical filesystem locations for the PyShare evaluation subsystem."""
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parents[2]
METHODS_ROOT = PACKAGE_ROOT / "methods"
CONFIG_ROOT = PROJECT_ROOT / "configs" / "evaluation"
RESULTS_ROOT = PROJECT_ROOT / "results" / "evaluation"
ADAPTER_RESULTS_ROOT = RESULTS_ROOT / "adapters"
SHARED_ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_MASTER = PROJECT_ROOT / "data" / "processed" / "cve_to_vf_evaluation.jsonl"
