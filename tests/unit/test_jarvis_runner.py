"""Smoke tests for the JARVIS subprocess wrapper.

These tests cover the pure-Python helpers (entry-module discovery, venv
detection, cache decision). Actual subprocess invocation is exercised
manually in tests/integration/ (not committed) — covering it here would
require a real JARVIS install on every machine.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pyshare.pipeline.project_scanner.jarvis_runner import (
    _discover_entry_modules,
    _find_venv_python,
    discover_entry_modules,
)


# ---------------------------------------------------------------------
# Entry module discovery
# ---------------------------------------------------------------------

class TestDiscoverEntryModules:
    def test_finds_top_level_py(self, tmp_path: Path):
        (tmp_path / "server.py").write_text("")
        (tmp_path / "client.py").write_text("")
        mods = discover_entry_modules(tmp_path)
        names = {m.name for m in mods}
        assert names == {"server.py", "client.py"}

    def test_skips_setup_conftest_manage(self, tmp_path: Path):
        for fn in ("setup.py", "conftest.py", "manage.py", "app.py"):
            (tmp_path / fn).write_text("")
        mods = discover_entry_modules(tmp_path)
        names = {m.name for m in mods}
        assert names == {"app.py"}  # only the real entry survives

    def test_skips_underscore_prefixed(self, tmp_path: Path):
        (tmp_path / "_private.py").write_text("")
        (tmp_path / "public.py").write_text("")
        mods = discover_entry_modules(tmp_path)
        assert {m.name for m in mods} == {"public.py"}

    def test_finds_top_level_packages(self, tmp_path: Path):
        # mypkg/__init__.py marks a package
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        # nested files don't count
        (pkg / "submod.py").write_text("")
        mods = discover_entry_modules(tmp_path)
        names = {str(m.relative_to(tmp_path)).replace("\\", "/")
                 for m in mods}
        assert "mypkg/__init__.py" in names
        assert "mypkg/submod.py" not in names

    def test_skips_venv_and_test_dirs(self, tmp_path: Path):
        for d in (".venv", "venv", "tests", "docs", "scripts",
                  "build", "dist", "__pycache__"):
            sub = tmp_path / d
            sub.mkdir()
            (sub / "__init__.py").write_text("")
        (tmp_path / "real.py").write_text("")
        mods = discover_entry_modules(tmp_path)
        assert {m.name for m in mods} == {"real.py"}

    def test_empty_project_returns_empty_list(self, tmp_path: Path):
        assert discover_entry_modules(tmp_path) == []

    def test_nonexistent_returns_empty(self, tmp_path: Path):
        assert discover_entry_modules(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------
# venv detection
# ---------------------------------------------------------------------

class TestFindVenvPython:
    def test_prefers_dotvenv_windows(self, tmp_path: Path):
        venv_py = tmp_path / ".venv" / "Scripts" / "python.exe"
        venv_py.parent.mkdir(parents=True)
        venv_py.write_text("")
        assert _find_venv_python(tmp_path) == venv_py

    def test_prefers_dotvenv_unix(self, tmp_path: Path):
        venv_py = tmp_path / ".venv" / "bin" / "python"
        venv_py.parent.mkdir(parents=True)
        venv_py.write_text("")
        assert _find_venv_python(tmp_path) == venv_py

    def test_falls_back_to_venv_dir(self, tmp_path: Path):
        # No .venv, but venv/ exists
        if sys.platform == "win32":
            venv_py = tmp_path / "venv" / "Scripts" / "python.exe"
        else:
            venv_py = tmp_path / "venv" / "bin" / "python"
        venv_py.parent.mkdir(parents=True)
        venv_py.write_text("")
        assert _find_venv_python(tmp_path) == venv_py

    def test_falls_back_to_sys_executable(self, tmp_path: Path):
        # No venv at all — should fall back to current interpreter.
        assert _find_venv_python(tmp_path) == Path(sys.executable)


# ---------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------

class TestCache:
    def test_cache_hit_skips_subprocess(self, tmp_path: Path, monkeypatch):
        """If output_path exists and force=False, run_jarvis returns
        immediately without invoking subprocess."""
        from pyshare.pipeline.project_scanner import jarvis_runner

        cached = tmp_path / ".pyshare" / "jarvis.json"
        cached.parent.mkdir()
        cached.write_text('{"foo": []}', encoding="utf-8")

        # Make subprocess.run unreachable — if it's called, test fails.
        def fail(*a, **kw):
            raise AssertionError("subprocess should not run on cache hit")
        monkeypatch.setattr(jarvis_runner.subprocess, "run", fail)

        result = jarvis_runner.run_jarvis(tmp_path)
        assert result == cached
