import ast
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules",
             "build", "dist", ".tox", "site-packages"}


def extract_functions_from_file(path: Path, repo_root: Path) -> list[dict]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []

    src_lines = source.splitlines()
    rel = str(path.relative_to(repo_root)).replace("\\", "/")
    out: list[dict] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            end = getattr(node, "end_lineno", start + 1)
            body = "\n".join(src_lines[start:end])
            out.append({
                "name": node.name,
                "qualname": _qualname(tree, node),
                "file": rel,
                "start_line": node.lineno,
                "end_line": end,
                "body": body,
                "docstring": ast.get_docstring(node) or "",
            })
    return out


def _qualname(tree: ast.AST, target: ast.AST) -> str:
    """Best-effort dotted qualname for a function (Class.method)."""
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    parts: list[str] = []
    node = target
    while node is not None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parts.append(node.name)
        node = parents.get(id(node))
    return ".".join(reversed(parts))


def parse_repo(repo_root: str | Path) -> list[dict]:
    repo_root = Path(repo_root).resolve()
    funcs: list[dict] = []
    for py in repo_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in py.parts):
            continue
        funcs.extend(extract_functions_from_file(py, repo_root))
    return funcs
