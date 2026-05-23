from pathlib import Path
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

    # Path to JARVIS CLI script (jarvis_cli.py from pythonJaRvis.github.io).
    # Required to auto-run JARVIS. If unset, the pipeline expects the
    # JSON output to already exist somewhere under the project.
    jarvis_cli_path: Path | None = None

    index_dir:     Path = Path.home() / ".pyshare" / "index"
    cve_cache_dir: Path = Path.home() / ".pyshare" / "cve"


settings = Settings()
