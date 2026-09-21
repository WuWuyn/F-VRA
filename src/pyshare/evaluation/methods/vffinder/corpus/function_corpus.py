"""Component 3: Function Corpus Generator (Python adaptation).

Original VFFinder (Java) uses:
  - javalang  → parse Java source, extract vars/params/strings
  - Soot      → generate call graph from compiled bytecode (.jar)

Python adaptation:
  - ast       → parse Python source (stdlib, no extra deps)
  - ast.walk  → build call graph statically (replaces Soot)
  - Same Graph + inline-expansion logic as the original

Entity extraction follows the same 6-channel design:
  APIName    → function name words
  APIClz     → class / module name words
  APIVar     → local variable names
  APIParaName→ parameter names
  APIParaType→ parameter type annotations
  APIString  → string literals + comments

Python-only addition:
  Docstring  → words from the function's docstring
"""

import ast
import os
import re
import json
import pickle
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..common.text_utils import (
    split_identifier,
    filter_meaningless,
    deduplicate_wordnet,
    _STOPWORDS,
    _STEMMER,
)
from .. import config


# ---------------------------------------------------------------------------
# Data class  (mirrors original APIEntity)
# Canonical home is common/models.py (main refactor); re-exported here so
# existing `from ..corpus.function_corpus import FunctionEntity` keeps working.
# ---------------------------------------------------------------------------

from ..common.models import FunctionEntity


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


MIN_IDENTIFIER_LEN = max(1, _env_int("VFF_MIN_IDENTIFIER_LEN", 2))
MIN_STRING_LEN = max(1, _env_int("VFF_MIN_STRING_LEN", 2))
MIN_COMMENT_ALPHA = max(1, _env_int("VFF_MIN_COMMENT_ALPHA", 1))


# ---------------------------------------------------------------------------
# AST helpers  (replaces javalang extractors)
# ---------------------------------------------------------------------------

def _source_of(node: ast.AST, source_lines: list[str]) -> str:
    """Return the source text for a function/class node."""
    try:
        return ast.get_source_segment("\n".join(source_lines), node) or ""
    except Exception:
        return ""


def extract_name_entity(func_name: str) -> list[str]:
    """APIName channel — split function name into words (replaces extractAPINameEntity)."""
    return split_identifier(func_name)


def extract_class_entity(class_name: str) -> list[str]:
    """APIClz channel — split class/module name (replaces extractAPIClzEntity)."""
    return split_identifier(class_name)


def extract_param_name_entity(args: ast.arguments) -> list[str]:
    """APIParaName channel — split parameter names (replaces extractAPIParaEntity)."""
    words: list[str] = []
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.arg not in ("self", "cls"):
            words.extend(split_identifier(arg.arg))
    if args.vararg:
        words.extend(split_identifier(args.vararg.arg))
    if args.kwarg:
        words.extend(split_identifier(args.kwarg.arg))
    return list(set(words))


def extract_param_type_entity(args: ast.arguments) -> list[str]:
    """APIParaType channel — split type annotation words (Python-specific)."""
    words: list[str] = []
    all_args = args.args + args.posonlyargs + args.kwonlyargs
    if args.vararg:
        all_args.append(args.vararg)
    if args.kwarg:
        all_args.append(args.kwarg)
    for arg in all_args:
        if arg.annotation:
            ann_str = ast.unparse(arg.annotation)
            for part in re.split(r"[|\[\],\s]+", ann_str):
                words.extend(split_identifier(part))
    return list(set(words))


def extract_variable_entity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """APIVar channel — local variable + attribute names (replaces extractAPICodeEntity/javalang).

    Single-letter names are usually loop noise, but two-letter tokens such as
    id/io can be vulnerability-relevant. The minimum is configurable through
    VFF_MIN_IDENTIFIER_LEN for ablation.
    """
    words: list[str] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Load)):
            if len(node.id) >= MIN_IDENTIFIER_LEN:
                words.extend(split_identifier(node.id))
        elif isinstance(node, ast.Attribute):
            if len(node.attr) >= MIN_IDENTIFIER_LEN:
                words.extend(split_identifier(node.attr))
    return list(set(words))


_URL_PATTERN = re.compile(r"https?://|www\.|\.com|\.org|\.io|\.py\b")
_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)


def extract_string_entity(func_node: ast.FunctionDef | ast.AsyncFunctionDef,
                          source_text: str) -> list[str]:
    """APIString channel — string literals + comments.

    Java equivalent (javalang) does not extract comments from the AST.
    Python adaptation extracts comments but skips lines containing URLs
    (e.g. '# See https://github.com/...') which generate domain-name noise
    like 'github', 'com', 'psf' that pollute the entity bag.

    Very short strings can be skipped via VFF_MIN_STRING_LEN; default keeps
    two-character tokens because ids and modes can be vulnerability-relevant.
    """
    words: list[str] = []

    # String literals from AST — skip very short ones and format strings
    for node in ast.walk(func_node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.strip()
            if len(val) >= MIN_STRING_LEN and not _URL_PATTERN.search(val):
                for tok in val.split():
                    words.extend(split_identifier(tok))

    # Inline comments — skip lines that contain URLs or have few alpha words.
    # Java's javalang does not extract comments; Python comments often contain
    # code-style remarks ("weird dance", "hacky workaround") that add noise.
    # Only extract comments that look like meaningful descriptions.
    for comment in _COMMENT_RE.findall(source_text):
        body = comment.lstrip("#").strip()
        if not body or _URL_PATTERN.search(body):
            continue
        alpha_toks = [
            t for t in body.split()
            if t.isalpha() and len(t) >= MIN_IDENTIFIER_LEN
        ]
        if len(alpha_toks) < MIN_COMMENT_ALPHA:
            continue
        for tok in alpha_toks:
            words.extend(split_identifier(tok))

    return list(set(words))


def extract_docstring_entity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Docstring channel — Python-specific, no Java equivalent."""
    doc = ast.get_docstring(func_node) or ""
    words: list[str] = []
    for tok in doc.split():
        words.extend(split_identifier(re.sub(r"[^a-zA-Z0-9_]", "", tok)))
    return list(set(words))


# ---------------------------------------------------------------------------
# Call graph  (replaces Soot .cg files)
# ---------------------------------------------------------------------------

class Graph:
    """Adjacency-matrix call graph — identical interface to original inline.py Graph."""

    def __init__(self, nodes: list[str], adjacency_matrix: list[list[int]]):
        self.nodes = nodes
        self.adjacency_matrix = adjacency_matrix

    def get_upstream(self, node: str) -> list[str]:
        if node not in self.nodes:
            return []
        idx = self.nodes.index(node)
        return [self.nodes[i] for i in range(len(self.nodes))
                if self.adjacency_matrix[i][idx] == 1]

    def get_downstream(self, node: str) -> list[str]:
        if node not in self.nodes:
            return []
        idx = self.nodes.index(node)
        return [self.nodes[i] for i in range(len(self.nodes))
                if self.adjacency_matrix[idx][i] == 1]


def build_call_graph(func_entities: list[FunctionEntity]) -> Graph:
    """Build an intra-package call graph using AST Call nodes.

    Replaces Soot-based .cg generation from the original.
    Only intra-package calls (functions whose name appears in func_entities) are recorded.
    """
    func_ids = {fe.func_id for fe in func_entities}
    name_to_ids: dict[str, list[str]] = {}
    for fe in func_entities:
        name_to_ids.setdefault(fe.name, []).append(fe.func_id)

    node_list = list(func_ids)
    n = len(node_list)
    matrix = [[0] * n for _ in range(n)]
    idx = {fid: i for i, fid in enumerate(node_list)}

    for fe in func_entities:
        if not fe.source:
            continue
        try:
            tree = ast.parse(fe.source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # direct call: f()
                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                # attribute call: obj.method()
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr
                else:
                    continue
                for callee_id in name_to_ids.get(callee_name, []):
                    i, j = idx[fe.func_id], idx[callee_id]
                    matrix[i][j] = 1

    return Graph(node_list, matrix)


# ---------------------------------------------------------------------------
# Inline expansion  (identical logic to original inline.py, Java-independent)
# ---------------------------------------------------------------------------

def _find_entity_by_id(func_entities: list[FunctionEntity],
                       func_id: str) -> Optional[FunctionEntity]:
    for fe in func_entities:
        if fe.func_id == func_id:
            return fe
    return None


def _function_statement_count(source: str) -> int | None:
    try:
        tree = ast.parse(textwrap.dedent(source or ""))
    except SyntaxError:
        return None
    node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )
    if node is None:
        return None
    body = list(node.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(getattr(body[0], "value", None), ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return len(body)


def inline_expand(func_entities: list[FunctionEntity],
                  call_graph: Graph,
                  max_lines: int = 5) -> list[FunctionEntity]:
    """Propagate callee entities up to short callers.

    Mirrors original extend_API_entity_until_no_change — language-independent logic.
    """
    short_funcs = [
        fe for fe in func_entities
        if (stmt_count := _function_statement_count(fe.source)) is not None
        and stmt_count <= max_lines
    ]

    todo = list(short_funcs)
    for fe in todo:
        origin = set(fe.entities)
        new_entities = set(origin)

        for callee_id in call_graph.get_downstream(fe.func_id):
            callee = _find_entity_by_id(func_entities, callee_id)
            if callee:
                new_entities |= set(callee.entities)

        if new_entities != origin:
            fe.entities = list(new_entities)
            for caller_id in call_graph.get_upstream(fe.func_id):
                caller = _find_entity_by_id(func_entities, caller_id)
                if caller and caller not in todo:
                    todo.append(caller)

    return func_entities


# ---------------------------------------------------------------------------
# Per-function entity pipeline  (mirrors extract_API_entity)
# ---------------------------------------------------------------------------

def _clean_combined(raw: list[str], stem: bool = True) -> list[str]:
    """Lowercase → stopword removal → POS filter → WordNet dedup → stem."""
    lowered = [w.lower() for w in raw]
    no_stop = [w for w in lowered if w not in _STOPWORDS]
    filtered = filter_meaningless(no_stop)
    deduped = deduplicate_wordnet(filtered)
    if stem:
        deduped = list({_STEMMER.stem(e) for e in deduped})
    return deduped


def extract_function_entity(func_node: ast.FunctionDef | ast.AsyncFunctionDef,
                            module_path: str,
                            class_name: str,
                            source_lines: list[str],
                            stem: bool = True) -> FunctionEntity:
    """Extract entity corpus for a single Python function.

    Mirrors extract_API_entity() with 6 channels + docstring.
    """
    func_name = func_node.name
    func_source = _source_of(func_node, source_lines)
    qualified = f"{class_name}.{func_name}" if class_name else func_name
    func_id = f"{module_path}::{qualified}"

    raw: list[str] = []
    raw += extract_name_entity(func_name)                          # APIName
    raw += extract_class_entity(class_name or Path(module_path).stem)  # APIClz
    raw += extract_param_name_entity(func_node.args)               # APIParaName
    raw += extract_param_type_entity(func_node.args)               # APIParaType
    raw += extract_variable_entity(func_node)                      # APIVar
    raw += extract_string_entity(func_node, func_source)           # APIString
    raw += extract_docstring_entity(func_node)                     # Docstring (Python-only)

    entities = _clean_combined(raw, stem=stem)

    return FunctionEntity(
        func_id=func_id,
        name=func_name,
        module=module_path,
        class_name=class_name,
        params=[a.arg for a in func_node.args.args],
        param_types=[
            ast.unparse(a.annotation) if a.annotation else ""
            for a in func_node.args.args
        ],
        source=func_source,
        entities=entities,
    )


# ---------------------------------------------------------------------------
# File-level parser
# ---------------------------------------------------------------------------

def parse_python_file(py_file: Path,
                      package_root: Path,
                      stem: bool = True) -> list[FunctionEntity]:
    """Parse one .py file and return FunctionEntity for every function/method."""
    source_text = py_file.read_text(encoding="utf-8", errors="ignore")
    module_path = str(py_file.relative_to(package_root)).replace("\\", "/")
    return parse_python_source(source_text, module_path, stem=stem)


_DEF_RE = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(([^)]*)", re.MULTILINE)


def _regex_fallback_functions(source_text: str,
                              module_path: str,
                              stem: bool = True) -> list[FunctionEntity]:
    """Best-effort function extraction for sources the py3 AST can't parse.

    Captures each `def name(params...)` via regex and builds an entity bag from
    the function name + parameter names (no body — the body can't be reliably
    tokenised without an AST). func_id = "<module_path>::<name>", matching the
    ground-truth convention. Class context is unavailable, so class_name="".
    """
    results: list[FunctionEntity] = []
    seen: set[str] = set()
    for m in _DEF_RE.finditer(source_text):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        params = [p.split("=")[0].split(":")[0].strip().lstrip("*")
                  for p in m.group(2).split(",")]
        params = [p for p in params if p and p not in ("self", "cls")]

        raw = extract_name_entity(name) + [Path(module_path).stem]
        for p in params:
            raw += split_identifier(p)
        results.append(FunctionEntity(
            func_id=f"{module_path}::{name}",
            name=name,
            module=module_path,
            class_name="",
            params=params,
            param_types=[],
            source="",
            entities=_clean_combined(raw, stem=stem),
        ))
    return results


def parse_python_source(source_text: str,
                        module_path: str,
                        stem: bool = True) -> list[FunctionEntity]:
    """Parse Python source TEXT (no file on disk) for every function/method.

    `module_path` is the path recorded in func_id (relative to the project
    root, forward-slashed). Used when reading source straight from a git
    object store so no working tree needs to be checked out.
    """
    try:
        tree = ast.parse(source_text, filename=module_path)
    except SyntaxError:
        # Python-2-only sources (old CVE-era projects: Zope 2011, ansible 2014,
        # django ≤1.x) can't be parsed by the py3 `ast`. Fall back to a regex
        # scan so every `def` still becomes a candidate function — matching how
        # the JSONL corpus handled unparseable functions (name-based entities).
        return _regex_fallback_functions(source_text, module_path, stem=stem)

    source_lines = source_text.splitlines()
    results: list[FunctionEntity] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_name = node.name
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    results.append(extract_function_entity(
                        item, module_path, class_name, source_lines, stem=stem))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # top-level function (not inside a class)
            parent_is_class = any(
                isinstance(p, ast.ClassDef)
                for p in ast.walk(tree)
                if node in ast.walk(p) and p is not node
            )
            if not parent_is_class:
                results.append(extract_function_entity(
                    node, module_path, "", source_lines, stem=stem))

    return results


# ---------------------------------------------------------------------------
# Package-level entry point
# ---------------------------------------------------------------------------

def build_function_corpus(
    package_dir: str | Path,
    output_path: str | Path | None = None,
    stem: bool = True,
    inline: bool = True,
) -> list[FunctionEntity]:
    """Build function corpus for an entire Python package directory.

    Parameters
    ----------
    package_dir : root directory of the package source (e.g. "Pillow-9.0.0/src/PIL")
    output_path : optional JSON file to write results
    stem        : apply Porter stemming
    inline      : expand short-function entities via call graph

    Returns
    -------
    List of FunctionEntity objects, one per function/method.
    """
    package_dir = Path(package_dir)
    all_entities: list[FunctionEntity] = []

    for py_file in sorted(package_dir.rglob("*.py")):
        all_entities.extend(parse_python_file(py_file, package_dir, stem=stem))

    if inline and all_entities:
        cg = build_call_graph(all_entities)
        all_entities = inline_expand(all_entities, cg)

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([fe.to_dict() for fe in all_entities],
                      f, indent=2, ensure_ascii=False)

    return all_entities


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Build function corpus from Python package source code."
    )
    parser.add_argument(
        "--package-dir", required=True,
        help="root directory of the package source (e.g. pillow-9.0.0/src/PIL)",
    )
    parser.add_argument(
        "--output",
        default=str(config.OUTPUT_DIR / "function_corpus.json"),
        help="path to write the function corpus JSON",
    )
    parser.add_argument(
        "--no-stem", action="store_true", help="disable Porter stemming"
    )
    parser.add_argument(
        "--no-inline", action="store_true", help="disable call-graph inline expansion"
    )
    args = parser.parse_args(argv)

    pkg = Path(args.package_dir)
    if not pkg.is_dir():
        print(f"Package directory not found: {pkg}", file=sys.stderr)
        return 1

    print(f"Parsing {pkg} ...")
    entities = build_function_corpus(
        pkg,
        output_path=args.output,
        stem=not args.no_stem,
        inline=not args.no_inline,
    )

    print(f"Done. {len(entities)} function(s) extracted.")
    print(f"Output: {args.output}")
    for fe in entities[:3]:
        print(f"  {fe.func_id}: {fe.entities[:5]} ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
