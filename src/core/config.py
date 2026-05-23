"""PyShare runtime configuration.

Settings are loaded from environment variables, with optional ``.env``
overrides. The ``.env`` file is searched in this order (first match
wins), so ``pyshare`` works no matter which directory it's launched
from:

    1. ``$PYSHARE_ENV_FILE`` (absolute path, explicit override)
    2. Current working directory: ``./.env``
    3. The pyshare package directory: ``<package>/.env``
    4. Two levels up from the package (when installed editable with
       ``src/`` layout): ``<pkg>/../../.env``
    5. User home: ``~/.pyshare/.env``
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_env_file() -> Path | None:
    """Resolve which .env file (if any) to load."""
    explicit = os.environ.get("PYSHARE_ENV_FILE")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p

    pkg_dir = Path(__file__).resolve().parent.parent  # <pkg>/src or <pkg>
    candidates = [
        Path.cwd() / ".env",
        pkg_dir / ".env",
        pkg_dir.parent / ".env",            # editable install: <pkg>/../.env
        pkg_dir.parent.parent / ".env",     # one more level up
        Path.home() / ".pyshare" / ".env",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


_ENV_FILE = _find_env_file()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE else None,
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

    @property
    def env_file_used(self) -> Path | None:
        """Path to the .env file actually loaded, if any. Useful for
        diagnostics (e.g. ``python -c 'from pyshare.core.config import
        settings; print(settings.env_file_used)'``)."""
        return _ENV_FILE


settings = Settings()
