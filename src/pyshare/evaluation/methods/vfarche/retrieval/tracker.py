from __future__ import annotations

import ast
import re
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .patch_diff import FilePatch, load_patch


_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\(")
_ATTR = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\b")
_ASSIGN = re.compile(r"\b(?:self\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


@dataclass
class TrackerCandidate:
    func: dict
    score: float = 0.0
    reasons: set[str] = field(default_factory=set)

    def add(self, score: float, reason: str) -> None:
        self.score += score
        self.reasons.add(reason)


class _FeatureVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: set[str] = set()
        self.refs: set[str] = set()
        self.assigns: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        name = _expr_name(node.func)
        if name:
            self.calls.add(name)
            self.calls.add(name.rsplit(".", 1)[-1])
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.refs.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.refs.add(node.attr)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for name in _target_names(target):
                self.assigns.add(name)
                self.refs.add(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        for name in _target_names(node.target):
            self.assigns.add(name)
            self.refs.add(name)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        for name in _target_names(node.target):
            self.assigns.add(name)
            self.refs.add(name)
        self.generic_visit(node)


def _expr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, (ast.Tuple, ast.List)):
        out: set[str] = set()
        for elt in node.elts:
            out.update(_target_names(elt))
        return out
    return set()


def _features(func: dict) -> _FeatureVisitor:
    visitor = _FeatureVisitor()
    try:
        visitor.visit(ast.parse(textwrap.dedent(func.get("body") or "")))
    except SyntaxError:
        pass
    visitor.refs.update(_IDENT.findall(func.get("qualname") or ""))
    visitor.refs.update(_IDENT.findall(func.get("name") or ""))
    return visitor


def _line_tokens(lines: list[str]) -> set[str]:
    out: set[str] = set()
    for line in lines:
        out.update(_IDENT.findall(line))
        out.update(_ATTR.findall(line))
        for call in _CALL.findall(line):
            out.add(call)
            out.add(call.rsplit(".", 1)[-1])
    return {x for x in out if len(x) > 1}


def _call_names(lines: list[str]) -> set[str]:
    out: set[str] = set()
    for line in lines:
        for call in _CALL.findall(line):
            out.add(call)
            out.add(call.rsplit(".", 1)[-1])
    return {x for x in out if len(x) > 1}


def _assign_names(lines: list[str]) -> set[str]:
    out: set[str] = set()
    for line in lines:
        out.update(_ASSIGN.findall(line))
        out.update(_ATTR.findall(line))
    return {x for x in out if len(x) > 1}


def _is_test_func(func: dict) -> bool:
    path = (func.get("file") or "").lower()
    name = (func.get("name") or "").lower()
    return (
        "/test" in path
        or path.startswith("test")
        or "/tests/" in path
        or name.startswith("test_")
    )


def non_test_functions(funcs: list[dict]) -> list[dict]:
    return [f for f in funcs if not _is_test_func(f)]


def _func_key(func: dict) -> str:
    return f"{func.get('file')}::{func.get('qualname')}::{func.get('start_line')}"


def _overlaps(func: dict, path: str, lines: set[int]) -> bool:
    if (func.get("file") or "") != path or not lines:
        return False
    return any(func["start_line"] <= line <= func["end_line"] for line in lines)


def _nearest_funcs(funcs: list[dict], path: str, line: int, radius: int = 12) -> list[dict]:
    same_file = [f for f in funcs if (f.get("file") or "") == path]
    if not same_file:
        return []
    inside = [f for f in same_file if f["start_line"] <= line <= f["end_line"]]
    if inside:
        return inside
    return [
        f for f in same_file
        if min(abs(line - f["start_line"]), abs(line - f["end_line"])) <= radius
    ]


def _add(store: dict[str, TrackerCandidate], func: dict, score: float, reason: str) -> None:
    key = _func_key(func)
    if key not in store:
        store[key] = TrackerCandidate(func=func)
    store[key].add(score, reason)


def select_with_tracker(
    repo_path: str | Path,
    cve: dict,
    funcs: list[dict],
    *,
    top_k: int = 100,
    max_depth: int = 2,
) -> list[dict]:
    """PATCH-PRESENT candidate selector.

    This is the Python adaptation of VFArCHE's Tracker: patch hunks are mapped
    to functions, then candidate scope is widened with static call/reference
    links so vulnerable functions related to but not directly modified by the
    patch can still survive into ranking.
    """
    vulnerable_ref = cve.get("vulnerable_ref") or cve.get("patch_commit")
    fix_commit = cve.get("fix_commit")
    if not vulnerable_ref or not fix_commit:
        return []

    patches = load_patch(repo_path, vulnerable_ref, fix_commit)
    if not patches:
        return []

    candidates: dict[str, TrackerCandidate] = {}
    funcs = non_test_functions(funcs)
    features = {_func_key(f): _features(f) for f in funcs}
    by_name: dict[str, list[dict]] = defaultdict(list)
    for func in funcs:
        by_name[func.get("name") or ""].append(func)
        by_name[(func.get("qualname") or "").rsplit(".", 1)[-1]].append(func)

    seed_keys: set[str] = set()
    target_calls: set[str] = set()
    target_refs: set[str] = set()

    for patch in patches:
        deleted_lines, added_lines = _patch_lines(patch, "-"), _patch_lines(patch, "+")
        deleted_calls, added_calls = _call_names(deleted_lines), _call_names(added_lines)
        target_calls.update(deleted_calls | added_calls)
        target_refs.update(_line_tokens(deleted_lines + added_lines))

        old_line_numbers = {
            ln.old_lineno
            for h in patch.hunks
            for ln in h.lines
            if ln.kind in {"-", " "} and ln.old_lineno is not None
        }
        deleted_line_numbers = {
            ln.old_lineno
            for h in patch.hunks
            for ln in h.lines
            if ln.kind == "-" and ln.old_lineno is not None
        }

        for func in funcs:
            if _overlaps(func, patch.old_path, deleted_line_numbers):
                _add(candidates, func, 10.0, "in-patch modified function")
                seed_keys.add(_func_key(func))

        if not any(_overlaps(f, patch.old_path, deleted_line_numbers) for f in funcs):
            for h in patch.hunks:
                for func in _nearest_funcs(funcs, patch.old_path, h.old_start):
                    _add(candidates, func, 7.0, "nearest patch function")
                    seed_keys.add(_func_key(func))

        if deleted_calls and added_calls:
            for name in deleted_calls | added_calls:
                for func in by_name.get(name, []):
                    _add(candidates, func, 6.0, "replaced method/class target")
                    seed_keys.add(_func_key(func))

        common_calls = deleted_calls & added_calls
        if common_calls:
            for func in funcs:
                feat = features[_func_key(func)]
                if feat.calls & common_calls:
                    _add(candidates, func, 4.0, "additional-arguments caller")

        config_refs = _assign_names(deleted_lines + added_lines)
        if config_refs:
            target_refs.update(config_refs)
            for func in funcs:
                feat = features[_func_key(func)]
                if feat.refs & config_refs:
                    _add(candidates, func, 3.0, "configuration/field reference")

        if not deleted_calls and not added_calls and not old_line_numbers:
            for func in funcs:
                if (func.get("file") or "") == patch.old_path:
                    _add(candidates, func, 2.0, "changed file fallback")

    frontier = set(seed_keys)
    for depth in range(max_depth):
        next_frontier: set[str] = set()
        seed_names = {
            candidates[key].func.get("name")
            for key in frontier
            if key in candidates
        }
        seed_names = {name for name in seed_names if name}
        for func in funcs:
            key = _func_key(func)
            feat = features[key]
            if key in frontier:
                continue
            if feat.calls & seed_names:
                _add(candidates, func, 3.0 / (depth + 1), "caller of tracked function")
                next_frontier.add(key)
            if feat.calls & target_calls:
                _add(candidates, func, 2.5 / (depth + 1), "caller of patch target")
                next_frontier.add(key)
            if feat.refs & target_refs:
                _add(candidates, func, 1.5 / (depth + 1), "data/reference flow")
                next_frontier.add(key)
        frontier = next_frontier
        if not frontier:
            break

    ranked = sorted(
        candidates.values(),
        key=lambda c: (
            c.score,
            "in-patch modified function" in c.reasons,
            -(c.func.get("start_line") or 0),
        ),
        reverse=True,
    )
    return [
        {
            **cand.func,
            "tracker_score": cand.score,
            "tracker_reasons": sorted(cand.reasons),
        }
        for cand in ranked[:top_k]
    ]


def _patch_lines(patch: FilePatch, kind: str) -> list[str]:
    return [
        line.text
        for hunk in patch.hunks
        for line in hunk.lines
        if line.kind == kind
    ]
