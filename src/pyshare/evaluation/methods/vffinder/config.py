"""Central configuration for the VFFinder pipeline.

Defines the filesystem paths (generated adapter data / runtime artifacts) and
the LLM endpoint used by Phase 1. The pipeline talks to any
OpenAI-API-compatible endpoint; the defaults below target OpenRouter.

All runtime settings come from the environment (loaded from the repository-root
``.env`` file via python-dotenv). See the root ``.env.example`` for a template. Configure:

    OPENROUTER_API_KEY  API key      (or VFFINDER_API_KEY)
    VFFINDER_BASE_URL   endpoint     (default: https://openrouter.ai/api/v1)
    VFFINDER_MODEL      chat model id; set explicitly for every research run
    VFFINDER_DATA_DIR   generated adapter/native input directory
    VFFINDER_OUTPUT_DIR runtime artifact directory

A real environment variable always takes precedence over the .env file.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from pyshare.evaluation.paths import PROJECT_ROOT, RESULTS_ROOT, SHARED_ENV_FILE

REPO_ROOT = PROJECT_ROOT

# One shared environment file for PyShare, VFFinder, and VFArCHE.
load_dotenv(SHARED_ENV_FILE)


def _configured_path(env_name: str, default: Path) -> Path:
    raw = os.environ.get(env_name)
    if not raw:
        return default
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


# Generated inputs and runtime artifacts are outside methods/ so the method tree
# stays source-only.
DATA_DIR = _configured_path(
    "VFFINDER_DATA_DIR",
    RESULTS_ROOT / "adapters" / "vffinder",
)

OUTPUT_DIR = _configured_path(
    "VFFINDER_OUTPUT_DIR",
    RESULTS_ROOT / "adapters" / "vffinder" / "native_output",
)

# --- LLM endpoint ---------------------------------------------------------
KEY_ENV = "OPENROUTER_API_KEY"
API_KEY = os.environ.get(KEY_ENV) or os.environ.get("VFFINDER_API_KEY")
BASE_URL = os.environ.get("VFFINDER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.environ.get("VFFINDER_MODEL")
ALLOW_WEAK_MODEL = os.environ.get("VFFINDER_ALLOW_WEAK_MODEL", "0") == "1"

# The paper used gpt-3.5-turbo-0613 at temperature 0; temperature 0 is kept
# for reproducibility regardless of which model is configured.
TEMPERATURE = 0.0


def validate_llm_model(model: str | None = None) -> str:
    """Return the configured model or raise on missing/obviously weak choices."""
    chosen = model or MODEL
    if not chosen:
        raise RuntimeError(
            "VFFINDER_MODEL is not set. The paper used gpt-3.5-turbo-0613 at "
            "temperature 0; choose an explicitly comparable or stronger chat "
            "model for research runs."
        )
    lowered = chosen.lower()
    # Trailing comma matters: ("...") is a string, and iterating it would test
    # single characters against the model id — rejecting nearly every model.
    weak_markers = (":free", "/free", "-free", " free")
    if not ALLOW_WEAK_MODEL and any(marker in lowered for marker in weak_markers):
        raise RuntimeError(
            f"VFFINDER_MODEL={chosen!r} looks like a free/weak model. For "
            "paper-fidelity runs use a model comparable to gpt-3.5-turbo-0613 "
            "or stronger. For smoke tests only, set VFFINDER_ALLOW_WEAK_MODEL=1."
        )
    return chosen


# --- spaCy model ----------------------------------------------------------
SPACY_MODEL = "en_core_web_sm"
