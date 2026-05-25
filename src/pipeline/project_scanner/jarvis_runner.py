"""Subprocess wrapper around JARVIS (jarvis_cli.py).

JARVIS needs to import the project's third-party dependencies (aiohttp,
requests, ...) to resolve cross-package edges. That means it must run
under the *project's* Python interpreter — typically ``<project>/.venv``
— not pyshare's interpreter.

Usage:
    from pyshare.pipeline.project_scanner import run_jarvis
    json_path = run_jarvis(Path("./myapp"))

Output is cached at ``<project>/.pyshare/jarvis.json``. Pass
``force=True`` to regenerate.

Configuration: set ``JARVIS_CLI_PATH`` in ``.env`` to the absolute path
of ``jarvis_cli.py`` from the JARVIS replication site.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

from pyshare.core.config import settings


DEFAULT_OUTPUT_REL = Path(".pyshare") / "jarvis.json"

# Same skip lists as _detect_app_packages_from_fs (kept in sync).
_SKIP_TOP_FILES = {"setup", "conftest", "manage"}
_SKIP_TOP_DIRS = {"tests", "test", "docs", "doc", "examples", "scripts",
                  ".venv", "venv", "env", "build", "dist", "__pycache__"}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def run_jarvis(
    project: Path,
    *,
    entry_modules: Optional[list[Path]] = None,
    output_path: Optional[Path] = None,
    force: bool = False,
    timeout: int = 600,
) -> Path:
    """Run JARVIS on ``project`` and return the path to the JSON output.

    Args:
        project:       Project root.
        entry_modules: .py files to seed JARVIS analysis from. If None,
                       auto-discovered (top-level non-helper .py files
                       and ``<package>/__init__.py``).
        output_path:   Where to write JSON. Default: ``<project>/.pyshare/jarvis.json``.
        force:         If False (default) and output_path exists, return
                       cached path without re-running.
        timeout:       Seconds to wait for JARVIS subprocess.

    Raises:
        FileNotFoundError: JARVIS CLI not configured, no .venv, or no
            entry modules discoverable.
        RuntimeError:      JARVIS subprocess returned non-zero.
        subprocess.TimeoutExpired: ``timeout`` exceeded.
    """
    project = project.resolve()

    if output_path is None:
        output_path = project / DEFAULT_OUTPUT_REL
    output_path = Path(output_path)

    if output_path.exists() and not force:
        return output_path

    jarvis_cli = _resolve_jarvis_cli()
    venv_python = _find_venv_python(project)
    modules = entry_modules or _discover_entry_modules(project)
    if not modules:
        raise FileNotFoundError(
            f"No entry .py modules found in {project}. Pass entry_modules "
            f"explicitly or place a top-level .py file in the project."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(venv_python),
        str(jarvis_cli),
        *[str(m) for m in modules],
        "--package", str(project),
        "--decy",
        "--precision",
        "-o", str(output_path),
    ]

    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        # JARVIS prints scanned module paths to stdout during normal
        # runs, errors usually end up in stderr. Surface both.
        raise RuntimeError(
            f"JARVIS failed (exit {proc.returncode}).\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stderr:\n{proc.stderr.strip()[:2000]}"
        )
    if not output_path.exists():
        raise RuntimeError(
            f"JARVIS exited 0 but did not write {output_path}.\n"
            f"stdout tail:\n{proc.stdout.strip()[-1000:]}"
        )

    return output_path


def discover_entry_modules(project: Path) -> list[Path]:
    """Public wrapper around the entry-module discovery heuristic."""
    return _discover_entry_modules(project)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _resolve_jarvis_cli() -> Path:
    p = settings.jarvis_cli_path
    if not p:
        raise FileNotFoundError(
            "JARVIS_CLI_PATH is not set. Edit .env and point it at "
            "jarvis_cli.py (see .env.example)."
        )
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(
            f"JARVIS_CLI_PATH points at a non-existent file: {p}"
        )
    return p


def _find_venv_python(project: Path) -> Path:
    """Locate the project's virtualenv Python interpreter.

    JARVIS must run with this interpreter so that ``import aiohttp``,
    ``import requests``, etc. resolve to the versions the project
    actually uses. Falls back to ``sys.executable`` with a warning
    only if no venv exists (which gives degraded results: TPL imports
    that aren't in pyshare's env will be unresolved).
    """
    candidates = [
        project / ".venv" / "Scripts" / "python.exe",  # Windows
        project / ".venv" / "bin" / "python",          # Unix
        project / "venv" / "Scripts" / "python.exe",
        project / "venv" / "bin" / "python",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Fall back to current interpreter — accepts degraded analysis.
    return Path(sys.executable)


def _discover_entry_modules(project: Path) -> list[Path]:
    """Find candidate entry .py files in the project root.

    Heuristic: top-level .py files (excluding setup/conftest/manage)
    and ``<package>/__init__.py`` for top-level packages.
    """
    modules: list[Path] = []
    if not project.is_dir():
        return modules
    for child in sorted(project.iterdir()):
        name = child.name
        if name.startswith((".", "_")):
            continue
        if child.is_dir():
            if name in _SKIP_TOP_DIRS:
                continue
            init = child / "__init__.py"
            if init.exists():
                modules.append(init)
        elif child.is_file() and child.suffix == ".py":
            stem = child.stem
            if stem in _SKIP_TOP_FILES or stem.startswith("_"):
                continue
            modules.append(child)
    return modules
