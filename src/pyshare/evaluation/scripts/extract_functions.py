"""extract_functions.py — build the shared per-repo function corpus (doc §11 step 4).

Walks every .py file under a checked-out repo and emits one record per
function/method with a `qualified_name` that matches the master benchmark's
convention, e.g.

    file_path  "synapse/federation/federation_server.py"
    class      FederationServer
    function   on_send_leave_request
    qualified  "synapse.federation.federation_server.FederationServer.on_send_leave_request"

This corpus is what ALL methods rank over (repository_functions scope) and what
predictions are matched against by qualified_name. Correctness of the
qualified_name convention here is critical — it is the join key to ground truth.

Record schema (one JSON per line):
    {"qualified_name", "function_name", "file_path", "start_line", "end_line", "source"}

CLI:
    python -m pyshare.evaluation.scripts.extract_functions --repo PATH --out corpus.jsonl
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import textwrap
from pathlib import Path


def module_path(rel_path: str) -> str:
    """'a/b/c.py' -> 'a.b.c' (the dotted module prefix of qualified_name)."""
    p = rel_path[:-3] if rel_path.endswith(".py") else rel_path
    return p.replace("\\", "/").strip("/").replace("/", ".")


def extract_file(source: str, rel_path: str) -> list[dict]:
    """Return one record per function/method in a single source file."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _fallback_extract_file(source, rel_path)
    mod = module_path(rel_path)
    lines = source.splitlines()
    records: list[dict] = []
    stack: list[str] = []  # enclosing class/function names

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def _func(self, node):
            qn = ".".join([mod, *stack, node.name])
            start = node.lineno
            end = getattr(node, "end_lineno", start) or start
            records.append({
                "qualified_name": qn,
                "function_name": node.name,
                "file_path": rel_path.replace("\\", "/"),
                "start_line": start,
                "end_line": end,
                "source": "\n".join(lines[start - 1:end]),
            })
            stack.append(node.name)        # nested funcs get parent in their qn
            self.generic_visit(node)
            stack.pop()

        visit_FunctionDef = _func
        visit_AsyncFunctionDef = _func

    Visitor().visit(tree)
    return records


_DEF_RE = re.compile(r"^(?P<indent>[ \t]*)(?:async[ \t]+)?def[ \t]+(?P<name>\w+)[ \t]*\(", re.MULTILINE)
_CLASS_RE = re.compile(r"^(?P<indent>[ \t]*)class[ \t]+(?P<name>\w+)\b", re.MULTILINE)


def _indent_width(line: str) -> int:
    expanded = line.expandtabs(4)
    return len(expanded) - len(expanded.lstrip(" "))


def _block_bounds(lines: list[str], start_idx: int, indent: int) -> tuple[int, int]:
    end = start_idx + 1
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        if line.strip() and _indent_width(line) <= indent:
            break
        end = i + 1
    return start_idx + 1, end


def _fallback_extract_file(source: str, rel_path: str) -> list[dict]:
    """Best-effort function extraction for files `ast` cannot parse.

    Old vulnerable refs can contain Python-2-only syntax. A regex fallback is
    weaker than AST, but it keeps candidate functions in the search pool instead
    of silently dropping the whole file.
    """
    mod = module_path(rel_path)
    lines = source.splitlines()
    keepends = source.splitlines(keepends=True)
    records: list[dict] = []
    stack: list[tuple[int, str]] = []
    seen: set[str] = set()

    for idx, line in enumerate(keepends):
        indent = _indent_width(line)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()

        class_match = _CLASS_RE.match(line)
        if class_match:
            stack.append((indent, class_match.group("name")))
            continue

        def_match = _DEF_RE.match(line)
        if not def_match:
            continue
        name = def_match.group("name")
        qn = ".".join([mod, *(n for _i, n in stack), name])
        if qn in seen:
            qn = f"{qn}@L{idx + 1}"
        seen.add(qn)
        start, end = _block_bounds(keepends, idx, indent)
        records.append({
            "qualified_name": qn,
            "function_name": name,
            "file_path": rel_path.replace("\\", "/"),
            "start_line": start,
            "end_line": end,
            "source": textwrap.dedent("\n".join(lines[start - 1:end])),
        })
        stack.append((indent, name))

    return records


def extract_corpus(repo_dir: Path) -> list[dict]:
    """Extract every function under `repo_dir` (recursively, from a working tree)."""
    out: list[dict] = []
    for py in sorted(repo_dir.rglob("*.py")):
        if ".git" in py.parts:
            continue
        try:
            source = py.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = py.relative_to(repo_dir).as_posix()
        out.extend(extract_file(source, rel))
    return out


def extract_corpus_from_sources(sources: dict[str, str]) -> list[dict]:
    """Extract every function from an in-memory {rel_path: source} mapping.

    Used by the repo-wide corpus builder, which reads sources straight from the
    git object store (no working tree) so it survives NTFS-illegal paths on
    Windows. Equivalent to extract_corpus but with no filesystem walk."""
    out: list[dict] = []
    try:
        from tqdm import tqdm
        iterator = tqdm(sorted(sources), desc="    extracting functions from files", leave=False)
    except ImportError:
        iterator = sorted(sources)
    for rel_path in iterator:
        out.extend(extract_file(sources[rel_path], rel_path))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract a repo's function corpus.")
    ap.add_argument("--repo", type=Path, required=True, help="Checked-out repo dir.")
    ap.add_argument("--out", type=Path, required=True, help="Output corpus JSONL.")
    args = ap.parse_args()

    corpus = extract_corpus(args.repo)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for rec in corpus:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Extracted {len(corpus)} functions -> {args.out}")


if __name__ == "__main__":
    main()
