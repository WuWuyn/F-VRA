from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def pypi_cache_root() -> Path:
    return Path(os.getenv("F_VRA_PYPI_CACHE_ROOT", "/var/lib/f-vra/pypi")).resolve()


def _run(args: list[str], cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True, timeout=180)


def _extract_archive(archive: Path, dest: Path) -> Path:
    if dest.exists():
        return _select_source_root(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".whl" or archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    elif archive.name.endswith((".tar.gz", ".tgz", ".tar.bz2")):
        with tarfile.open(archive) as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                tf.extractall(dest)
    else:
        raise RuntimeError(f"Unsupported package archive: {archive.name}")
    return _select_source_root(dest)


def _select_source_root(dest: Path) -> Path:
    children = [child for child in dest.iterdir() if child.is_dir() and not child.name.endswith(".dist-info")]
    if len(children) == 1:
        return children[0]
    return dest


def fetch_package_source(package: str, version: str, *, cache_root: Path | None = None) -> Path | None:
    if not package or not version:
        return None
    cache = (cache_root or pypi_cache_root()) / package.replace("/", "_").lower() / version
    source_dir = cache / "source"
    if source_dir.exists():
        return _select_source_root(source_dir)

    download_dir = cache / "download"
    if download_dir.exists():
        shutil.rmtree(download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)

    spec = f"{package}=={version}"
    try:
        _run([sys.executable, "-m", "pip", "download", "--no-deps", "--no-binary", ":all:", "--dest", str(download_dir), spec])
    except Exception:
        try:
            _run([sys.executable, "-m", "pip", "download", "--no-deps", "--dest", str(download_dir), spec])
        except Exception:
            return None

    archives = sorted(download_dir.iterdir(), key=lambda path: path.name)
    if not archives:
        return None
    try:
        return _extract_archive(archives[0], source_dir)
    except Exception:
        return None
