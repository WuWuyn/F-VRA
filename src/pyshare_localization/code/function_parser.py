from __future__ import annotations

import ast
from pathlib import Path

from pyshare_localization.models import FunctionInfo

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    ".tox",
    ".pytest_cache",
    "site-packages",
    "tests",
    "test",
}


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in node.elts:
            names.update(_target_names(item))
        return names
    if isinstance(node, ast.Attribute):
        name = _dotted_name(node)
        return {name} if name else set()
    return set()


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, source: str, relative_path: str) -> None:
        self.lines = source.splitlines()
        self.relative_path = relative_path
        self.scope: list[str] = []
        self.functions: list[FunctionInfo] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect(node, is_async=True)

    def _collect(self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool) -> None:
        qualname = ".".join([*self.scope, node.name])
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        calls: set[str] = set()
        referenced: set[str] = set()
        assigned: set[str] = set()
        local_types: dict[str, str] = {}
        parameters = {
            arg.arg
            for arg in [
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ]
        }
        if node.args.vararg:
            parameters.add(node.args.vararg.arg)
        if node.args.kwarg:
            parameters.add(node.args.kwarg.arg)
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _dotted_name(child.func)
                if name:
                    calls.add(name)
            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    assigned.update(_target_names(target))
                    if (
                        isinstance(target, ast.Name)
                        and isinstance(child.value, ast.Call)
                        and (callee := _dotted_name(child.value.func))
                    ):
                        local_types[target.id] = callee.split(".")[-1]
            elif isinstance(child, ast.For):
                assigned.update(_target_names(child.target))
            elif isinstance(child, ast.With):
                for item in child.items:
                    if item.optional_vars:
                        assigned.update(_target_names(item.optional_vars))
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                referenced.add(child.id)

        self.functions.append(
            FunctionInfo(
                function_name=node.name,
                qualname=qualname,
                file_path=self.relative_path,
                start_line=start,
                end_line=end,
                source="\n".join(self.lines[start - 1 : end]),
                docstring=ast.get_docstring(node) or "",
                calls=calls,
                referenced_names=referenced,
                assigned_names=assigned,
                parameter_names=parameters,
                local_types=local_types,
                decorators=[
                    name for name in (_dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
                                      for dec in node.decorator_list) if name
                ],
                is_async=is_async,
            )
        )

        self.scope.append(node.name)
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)
        self.scope.pop()


def extract_functions_from_file(path: Path, repo_root: Path) -> list[FunctionInfo]:
    try:
        source = path.read_text(encoding="utf-8-sig", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, ValueError, RecursionError):
        return []

    relative = path.relative_to(repo_root).as_posix()
    collector = _FunctionCollector(source, relative)
    collector.visit(tree)
    return collector.functions


def parse_repository(repo_root: str | Path) -> list[FunctionInfo]:
    root = Path(repo_root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Repository path is not a directory: {root}")

    functions: list[FunctionInfo] = []
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        functions.extend(extract_functions_from_file(path, root))
    return functions


def parse_repo(repo_root: str | Path) -> list[dict]:
    """Return parsed functions as dictionaries for VFloc-style integrations."""
    return [
        {
            "name": func.function_name,
            "qualname": func.qualname,
            "file": func.file_path,
            "start_line": func.start_line,
            "end_line": func.end_line,
            "body": func.source,
            "docstring": func.docstring,
        }
        for func in parse_repository(repo_root)
    ]
