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

    llm_provider: str = "openai"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-oss-120b:free"
    openrouter_embedding_model: str = "nvidia/llama-nemotron-embed-vl-1b-v2:free"

    @property
    def llm_api_key(self) -> str:
        return self.openrouter_api_key if self.llm_provider == "openrouter" else self.openai_api_key

    @property
    def llm_base_url(self) -> str | None:
        return "https://openrouter.ai/api/v1" if self.llm_provider == "openrouter" else None

    @property
    def llm_model(self) -> str:
        override = os.getenv("LLM_MODEL_OVERRIDE")
        if override:
            return override
        return self.openrouter_model if self.llm_provider == "openrouter" else self.openai_model

    @property
    def embedding_model(self) -> str:
        return os.getenv("EMBEDDING_MODEL_OVERRIDE") or self.openrouter_embedding_model


settings = Settings()
