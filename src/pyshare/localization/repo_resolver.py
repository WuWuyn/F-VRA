import re
import subprocess
from pathlib import Path

from pyshare.core.config import settings


def _repo_name(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", name)


def clone_or_update(repo_url: str, commit: str | None = None) -> Path:
    """Clone repo into REPO_CACHE_DIR/<repo_name>. Checkout commit if given."""
    name = _repo_name(repo_url)
    dest = settings.repo_cache_dir / name
    settings.repo_cache_dir.mkdir(parents=True, exist_ok=True)

    if not dest.exists():
        subprocess.run(
            ["git", "clone", "--quiet", repo_url, str(dest)],
            check=True,
        )

    if commit:
        subprocess.run(["git", "-C", str(dest), "fetch", "--quiet", "--all"], check=False)
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "--quiet", commit],
            check=True,
        )

    return dest
