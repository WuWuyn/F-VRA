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
    local_llm_api_key: str = ""
    local_llm_base_url: str = "https://quatmo-api.iahn.hanoi.vn/v1"
    local_llm_model: str = "qwen3-coder"
    local_embedding_api_key: str = ""
    local_embedding_base_url: str = "https://quatmo-api.iahn.hanoi.vn/v1"
    local_embedding_model: str = "qwen3-embedding"
    @property
    def llm_api_key(self) -> str:
        return self.local_llm_api_key

    @property
    def llm_base_url(self) -> str:
        return self.local_llm_base_url

    @property
    def llm_model(self) -> str:
        override = os.getenv("LLM_MODEL_OVERRIDE")
        if override:
            return override
        return self.local_llm_model

    @property
    def embedding_api_key(self) -> str:
        return self.local_embedding_api_key or self.local_llm_api_key

    @property
    def embedding_base_url(self) -> str:
        return self.local_embedding_base_url

    @property
    def embedding_model(self) -> str:
        override = os.getenv("EMBEDDING_MODEL_OVERRIDE")
        if override:
            return override
        return self.local_embedding_model

settings = Settings()
