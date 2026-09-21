import re
import subprocess
from pathlib import Path

from pyshare.evaluation.methods.vfarche.config import REPO_CACHE_DIR


def _repo_name(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", name)


def _run_git(args: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _configure_python_sparse_checkout(dest: Path) -> None:
    """Limit the Windows working tree to Python files.

    Some benchmark repos contain test fixtures with filenames that cannot be
    created on Windows (for example timestamps with ':'). Git can still fetch
    the objects; sparse checkout keeps those paths out of the working tree.
    """
    _run_git(["-C", str(dest), "config", "core.sparseCheckout", "true"])
    _run_git(["-C", str(dest), "config", "core.sparseCheckoutCone", "false"], check=False)
    info_dir = dest / ".git" / "info"
    info_dir.mkdir(parents=True, exist_ok=True)
    (info_dir / "sparse-checkout").write_text("/*.py\n/**/*.py\n", encoding="utf-8")


def _clear_stale_locks(dest: Path) -> None:
    git_dir = dest / ".git"
    for name in ("index.lock", "config.lock"):
        lock = git_dir / name
        if lock.exists():
            try:
                lock.unlink()
            except OSError:
                pass


def clone_or_update(repo_url: str, commit: str | None = None) -> Path:
    """Clone repo into REPO_CACHE_DIR/<repo_name>. Checkout commit if given."""
    name = _repo_name(repo_url)
    dest = REPO_CACHE_DIR / name

    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", "--quiet", "--no-checkout", repo_url, str(dest)])

    _clear_stale_locks(dest)
    _configure_python_sparse_checkout(dest)

    target = commit or "HEAD"
    if commit:
        _run_git(["-C", str(dest), "fetch", "--quiet", "--all"], check=False)

    try:
        _run_git(["-C", str(dest), "checkout", "--quiet", "--force", target])
    except subprocess.CalledProcessError:
        _clear_stale_locks(dest)
        _configure_python_sparse_checkout(dest)
        _run_git(["-C", str(dest), "checkout", "--quiet", "--force", target])

    return dest
