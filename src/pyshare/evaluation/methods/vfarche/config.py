import os
from pathlib import Path
from dotenv import load_dotenv
from pyshare.evaluation.paths import PROJECT_ROOT, RESULTS_ROOT, SHARED_ENV_FILE

REPO_ROOT = PROJECT_ROOT
load_dotenv(SHARED_ENV_FILE)


# ───────────────────────────── LLM provider ─────────────────────────────
# Supported providers (all use OpenAI-compatible API):
#   openai      → https://api.openai.com/v1
#   openrouter  → https://openrouter.ai/api/v1   (1 key, 100+ models incl. free)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai").lower().strip()


_DEFAULT_EMBED = {
    "openai": "text-embedding-3-small",
    "openrouter": "nvidia/llama-nemotron-embed-vl-1b-v2:free",
}


def _llm_settings(provider: str) -> tuple[str, str, str, str]:
    """Return (base_url, api_key, chat_model, embed_model) for the given provider."""
    if provider == "openai":
        return (
            os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            os.environ.get("OPENAI_API_KEY", ""),
            os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            os.environ.get("OPENAI_EMBEDDING_MODEL", _DEFAULT_EMBED["openai"]),
        )
    if provider == "openrouter":
        return (
            os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            os.environ.get("OPENROUTER_API_KEY", ""),
            os.environ.get(
                "OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"
            ),
            os.environ.get("OPENROUTER_EMBEDDING_MODEL", _DEFAULT_EMBED["openrouter"]),
        )
    raise ValueError(
        f"Unknown LLM_PROVIDER={provider!r}. Supported: openai, openrouter."
    )


LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, EMBEDDING_MODEL = _llm_settings(LLM_PROVIDER)

# CLI overrides
if os.environ.get("LLM_MODEL_OVERRIDE"):
    LLM_MODEL = os.environ["LLM_MODEL_OVERRIDE"]
if os.environ.get("EMBEDDING_MODEL_OVERRIDE"):
    EMBEDDING_MODEL = os.environ["EMBEDDING_MODEL_OVERRIDE"]

# A chat-compatible gateway need not serve embedding models. Overrides are
# explicit: never silently send source code to a different provider.
EMBEDDING_BASE_URL = os.environ.get("EMBEDDING_BASE_URL", LLM_BASE_URL)
EMBEDDING_API_KEY = os.environ.get("EMBEDDING_API_KEY", LLM_API_KEY)


# ───────────────────────────── MongoDB ─────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "vfarche")
COLLECTION_NAME = "topk_results"


# ───────────────────────────── Repo cache ─────────────────────────────
_repo_cache_value = os.environ.get(
    "REPO_CACHE_DIR", str(RESULTS_ROOT / "adapters" / "vfarche" / "repo_cache")
)
REPO_CACHE_DIR = Path(_repo_cache_value).expanduser()
if not REPO_CACHE_DIR.is_absolute():
    REPO_CACHE_DIR = REPO_ROOT / REPO_CACHE_DIR
REPO_CACHE_DIR = REPO_CACHE_DIR.resolve()
REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ───────────────────────────── Pipeline knobs ─────────────────────────────
BM25_TOP_K = 100
LLM_TOP_K = 20
LLM_BATCH_SIZE = 10        # functions per batch for chat rerank
EMBEDDING_BATCH_SIZE = 16  # functions per batch for embedding rank
