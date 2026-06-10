from pathlib import Path
import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = ""
    neo4j_uri:         str = "bolt://localhost:7687"
    neo4j_user:        str = "neo4j"
    neo4j_password:    str = ""

    index_dir:     Path = Path.home() / ".pyshare" / "index"
    cve_cache_dir: Path = Path.home() / ".pyshare" / "cve"
    repo_cache_dir: Path = Path.home() / ".pyshare" / "repos"

    bm25_top_k: int = 100
    llm_top_k: int = 20
    llm_batch_size: int = 10
    embedding_batch_size: int = 16
    github_token: str = ""
    nvd_api_key: str = ""
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-4o-mini"
    openrouter_embedding_model: str = "qwen/qwen3-embedding-0.6b"
    openrouter_rerank_model: str = ""
    openrouter_http_referer: str = ""
    openrouter_app_title: str = ""

    @property
    def llm_api_key(self) -> str:
        return self.openrouter_api_key

    @property
    def llm_base_url(self) -> str:
        return "https://openrouter.ai/api/v1"

    @property
    def llm_model(self) -> str:
        override = os.getenv("LLM_MODEL_OVERRIDE")
        if override:
            return override
        return self.openrouter_model

settings = Settings()
