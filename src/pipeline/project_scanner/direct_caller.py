"""AST-grep project source for direct callers of a vulnerable function.

JARVIS (even with --decy) frequently fails to trace into pip-installed
TPLs (e.g. yaml, jinja2, sqlalchemy). Without that bridge, the call
graph has no edge from app code to ``yaml.load``, and reachability
returns NOT_AFFECTED even when the project clearly calls the vulnerable
function.

This module fixes the gap with a complementary AST scan: walk every
.py file in the project, find function definitions whose body invokes
``<vf_short_name>(...)`` (matching either ``foo.<name>(...)`` attribute
calls or bare ``<name>(...)`` calls), and return the list of
(qname, file, line) tuples. The caller then injects synthetic
``app_function -> vf_qname`` edges into the CallGraph, restoring the
boundary that JARVIS missed.

Mirrors PyReach's `find_direct_functions()` (Wang et al., APSEC 2025),
which also relies on this AST-grep step rather than fully trusting the
call-graph builder to bridge into TPLs.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from pyshare.pipeline.project_scanner.jarvis_runner import (
    _SKIP_TOP_DIRS,
    _SKIP_TOP_FILES,
)


@dataclass(frozen=True)
class DirectCaller:
    """An app function that directly invokes a vulnerable-function name."""
    qname: str          # e.g. "myapp.api.parse_config"
    file: str           # absolute path
    line: int           # function definition line
    matched_call: str   # how it was matched: "name" or "attr"


def vf_short_name(vf_qname: str) -> str:
    """Extract the short function name from a qname.

    Examples:
        yaml.load                       -> load
        Crypto.Cipher._mode_ecb.EcbMode.encrypt -> encrypt
        sqlalchemy.orm.query.Query.order_by     -> order_by
    """
    return vf_qname.rsplit(".", 1)[-1]


def find_direct_callers(
    project: Path,
    vf_qname: str,
    app_packages: set[str] | None = None,  # kept for backward compat; ignored
) -> list[DirectCaller]:
    """Walk the project tree and return all functions whose body calls
    ``<short_name_of_vf>(...)``.

    Matches both:
      - Attribute calls:  ``something.<name>(...)``
      - Bare calls:       ``<name>(...)`` (imported via ``from x import name``)

    The match is purely lexical on the short name; it does not verify
    that the symbol resolves to the actual ``vf_qname`` module. That
    yields some false positives (e.g. an unrelated ``foo.load(...)``),
    which is the same trade-off PyReach accepts; downstream LLM
    reasoning is meant to filter those.

    ``app_packages`` is kept as a no-op argument for callers that still
    pass it. The scan now considers every .py file under the project
    that isn't in a skip directory, because real-world Python projects
    routinely contain folders without ``__init__.py`` (implicit
    namespace packages, sibling source dirs, etc.).
    """
    short = vf_short_name(vf_qname)
    callers: list[DirectCaller] = []

    for py_file in _iter_app_py_files(project):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        # Derive module qname directly from the relative path; no
        # app_packages gate so namespace-style folders are included.
        module_qname = _module_qname_loose(py_file, project)
        if module_qname is None:
            continue

        for func in _iter_function_defs(tree):
            matched = _function_calls(func, short)
            if matched:
                full_qname = _build_func_qname(module_qname, func, tree)
                callers.append(DirectCaller(
                    qname=full_qname,
                    file=str(py_file),
                    line=func.lineno,
                    matched_call=matched,
                ))
    return callers


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _iter_app_py_files(project: Path):
    """Yield .py files under project that look like app code.

    Includes any subfolder that isn't in the junk-dir blacklist,
    regardless of whether it has __init__.py — real Python projects
    frequently use implicit namespace packages or sibling source dirs.
    """
    if not project.is_dir():
        return
    for child in sorted(project.iterdir()):
        name = child.name
        if name.startswith("."):
            continue
        if child.is_dir():
            if name in _SKIP_TOP_DIRS:
                continue
            yield from _walk_py(child)
        elif child.is_file() and child.suffix == ".py":
            stem = child.stem
            if stem in _SKIP_TOP_FILES:
                continue
            yield child


def _walk_py(folder: Path):
    """Recursively yield .py files under folder, skipping junk dirs."""
    for entry in sorted(folder.iterdir()):
        name = entry.name
        if name.startswith((".", "_")) and name != "__init__.py":
            continue
        if entry.is_dir():
            if name in _SKIP_TOP_DIRS:
                continue
            yield from _walk_py(entry)
        elif entry.is_file() and entry.suffix == ".py":
            yield entry


def _module_qname_loose(py_file: Path, project: Path) -> str | None:
    """Derive a dotted module qname from a file path under the project.

    No app_packages gate: any .py file under the project tree (that
    wasn't filtered by ``_iter_app_py_files``) gets a qname.
    """
    try:
        rel = py_file.resolve().relative_to(project.resolve())
    except ValueError:
        return None
    parts = list(rel.with_suffix("").parts)
    if not parts:
        return None
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else None


def _iter_function_defs(tree: ast.AST):
    """Yield every FunctionDef / AsyncFunctionDef in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _function_calls(func: ast.AST, short_name: str) -> str:
    """Return 'attr' / 'name' / '' depending on how the function body
    invokes ``short_name(...)``."""
    for sub in ast.walk(func):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        if isinstance(f, ast.Attribute) and f.attr == short_name:
            return "attr"
        if isinstance(f, ast.Name) and f.id == short_name:
            return "name"
    return ""


def _build_func_qname(module_qname: str, func: ast.AST, tree: ast.AST) -> str:
    """Return ``module.[Class.]<func_name>`` if the function is nested in
    a class, else ``module.<func_name>``."""
    func_name = func.name
    # Find enclosing class via a simple parent scan: ast doesn't track
    # parents, so we re-walk the tree once.
    for cls in ast.walk(tree):
        if isinstance(cls, ast.ClassDef):
            for child in ast.walk(cls):
                if child is func:
                    return f"{module_qname}.{cls.name}.{func_name}"
    return f"{module_qname}.{func_name}"
