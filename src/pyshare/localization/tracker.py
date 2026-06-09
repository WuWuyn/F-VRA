from __future__ import annotations

from collections import defaultdict, deque

from pyshare.localization.models import FunctionInfo
from pyshare.localization.patch import PatchAnalysis


def _matches_file(function: FunctionInfo, patch_file: str) -> bool:
    return function.file_path == patch_file or function.file_path.endswith("/" + patch_file)


def _contains_changed_line(function: FunctionInfo, lines: set[int]) -> bool:
    return any(function.start_line <= line <= function.end_line for line in lines)


def track_patch_candidates(
    functions: list[FunctionInfo],
    patch: PatchAnalysis,
    *,
    max_depth: int = 2,
) -> dict[str, set[str]]:
    evidence: dict[str, set[str]] = defaultdict(set)
    by_simple: dict[str, list[FunctionInfo]] = defaultdict(list)
    for function in functions:
        by_simple[function.function_name].append(function)

    seeds: set[str] = set()
    for change in patch.files:
        for function in functions:
            if not _matches_file(function, change.file_path):
                continue
            if _contains_changed_line(function, change.old_lines | change.new_lines):
                seeds.add(function.identity)
                evidence[function.identity].add("function overlaps changed patch lines")

    for name in patch.called_names:
        for function in by_simple.get(name, []):
            seeds.add(function.identity)
            evidence[function.identity].add(f"function name appears in changed invocation: {name}")

    for function in functions:
        globals_hit = function.referenced_names & patch.changed_globals
        if globals_hit:
            seeds.add(function.identity)
            evidence[function.identity].add(
                "references changed configuration/global: " + ", ".join(sorted(globals_hit))
            )

    by_id = {function.identity: function for function in functions}
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    for caller in functions:
        for called in caller.calls:
            simple = called.split(".")[-1]
            for callee in by_simple.get(simple, []):
                callers[callee.identity].add(caller.identity)
                callees[caller.identity].add(callee.identity)

    queue = deque((seed, 0) for seed in seeds)
    visited = set(seeds)
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbour in callers[current]:
            evidence[neighbour].add(f"calls patch-related function {by_id[current].qualname}")
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))
        for neighbour in callees[current]:
            evidence[neighbour].add(f"called by patch-related function {by_id[current].qualname}")
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))

    return dict(evidence)
