"""Runtime config for vfloc-py.

Reads .env (via python-dotenv) and exposes the constants that the rest of the
package imports. CLI flags in vfloc.cli set LLM_MODEL_OVERRIDE / EMBEDDING_MODEL_OVERRIDE
in the environment *before* importing this module, so we honour them here.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai").strip().lower()

if LLM_PROVIDER == "openrouter":
    LLM_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
    LLM_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip()
    _DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-oss-120b:free").strip()
    _DEFAULT_EMBEDDING = os.environ.get(
        "OPENROUTER_EMBEDDING_MODEL", "nvidia/llama-nemotron-embed-vl-1b-v2:free"
    ).strip()
elif LLM_PROVIDER == "openai":
    LLM_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
    LLM_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
    _DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()
    _DEFAULT_EMBEDDING = os.environ.get("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small").strip()
else:
    raise RuntimeError(
        f"LLM_PROVIDER='{LLM_PROVIDER}' không hợp lệ. Chỉ chấp nhận 'openai' hoặc 'openrouter'."
    )

LLM_MODEL = os.environ.get("LLM_MODEL_OVERRIDE", "").strip() or _DEFAULT_MODEL
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL_OVERRIDE", "").strip() or _DEFAULT_EMBEDDING

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017").strip()
MONGO_DB = os.environ.get("MONGO_DB", "vfloc_py").strip()
COLLECTION_NAME = os.environ.get("MONGO_COLLECTION", "topk_results").strip()

REPO_CACHE_DIR = Path(os.environ.get("REPO_CACHE_DIR", "./repo_cache")).resolve()
REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)

BM25_TOP_K = int(os.environ.get("BM25_TOP_K", "100"))
LLM_TOP_K = int(os.environ.get("LLM_TOP_K", "20"))
LLM_BATCH_SIZE = int(os.environ.get("LLM_BATCH_SIZE", "10"))
EMBEDDING_BATCH_SIZE = int(os.environ.get("EMBEDDING_BATCH_SIZE", "32"))