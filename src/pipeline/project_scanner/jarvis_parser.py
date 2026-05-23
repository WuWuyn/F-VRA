"""Parse JARVIS call-graph JSON into a typed, cleaned CallGraph.

JARVIS output is a flat dict ``{caller_qname: [callee_qname, ...]}``.
This module:
  1. Classifies each qname into a FuncKind (app/tpl/stdlib/builtin/...).
  2. Detects candidate entry points (top-level app functions).
  3. Optionally prunes noise (builtins, type methods, unresolved names,
     and nodes unreachable from app code).

Run standalone for quick inspection:
    python jarvis_parser.py <jarvis.json> <app_pkg1,app_pkg2,...>
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

# Python 3.10+ ships a frozenset of all stdlib module names. Used to
# distinguish stdlib (os, asyncio, ssl, ...) from 3rd-party (aiohttp,
# requests, ...).
STDLIB_MODULES: frozenset[str] = frozenset(sys.stdlib_module_names)


class FuncKind(str, Enum):
    APP = "app"                  # project code
    TPL = "tpl"                  # 3rd-party (aiohttp, yarl, requests, ...)
    STDLIB = "stdlib"            # asyncio, os, ssl, urllib, ...
    BUILTIN = "builtin"          # <builtin>.print, <builtin>.range, ...
    TYPE_METHOD = "type_method"  # <str>.split, <map>.items, ...
    UNRESOLVED = "unresolved"    # bare names: append, extend, pop, index


@dataclass(frozen=True)
class FunctionNode:
    qname: str
    kind: FuncKind
    is_entry: bool = False


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str


@dataclass
class CallGraph:
    nodes: dict[str, FunctionNode]
    edges: list[CallEdge]
    project_id: str = ""

    def stats(self) -> dict[str, int]:
        c: dict[str, int] = {k.value: 0 for k in FuncKind}
        for n in self.nodes.values():
            c[n.kind.value] += 1
        c["_total_nodes"] = len(self.nodes)
        c["_total_edges"] = len(self.edges)
        c["_entries"] = sum(1 for n in self.nodes.values() if n.is_entry)
        return c


def classify(qname: str, app_packages: frozenset[str]) -> FuncKind:
    """Map a qname to its FuncKind based on naming convention."""
    if qname.startswith("<builtin>."):
        return FuncKind.BUILTIN
    if qname.startswith("<") and ">." in qname[:30]:
        return FuncKind.TYPE_METHOD
    if "." not in qname:
        return FuncKind.UNRESOLVED
    root = qname.split(".", 1)[0]
    if root in app_packages:
        return FuncKind.APP
    if root in STDLIB_MODULES:
        return FuncKind.STDLIB
    return FuncKind.TPL


def auto_detect_app_packages(raw: dict) -> set[str]:
    """Infer the project's top-level package names from JARVIS output.

    Rule: a JARVIS key with no dot and no angle brackets (e.g.
    ``"server"``) is a module-level entry. It is treated as a project
    package candidate iff:
      1. At least one of its listed callees uses it as a qname root
         (e.g. ``"server.main"``) — filters out bare unresolved names
         like ``"append"``.
      2. It is NOT in the Python stdlib — JARVIS emits stdlib modules
         (``"os"``, ``"logging"``, ``"threading"``) with the same
         pattern, and those are not project code.

    NOTE: This is a fallback. Prefer explicit ``app_packages`` from
    the project filesystem (see ``pipeline.reachability_query``).
    TPL packages like ``attr`` or ``typing_extensions`` can still slip
    through because they also have module-level statements; pass an
    explicit list to override.
    """
    candidates: set[str] = set()
    for caller, callees in raw.items():
        if not caller or "." in caller or caller.startswith("<"):
            continue
        if caller in STDLIB_MODULES:
            continue
        prefix = caller + "."
        if any(c and c.startswith(prefix) for c in callees):
            candidates.add(caller)
    return candidates


def parse_jarvis(
    json_path: Path | str,
    app_packages: set[str] | frozenset[str] | None = None,
    project_id: str = "",
) -> CallGraph:
    """Convert raw JARVIS JSON to a typed CallGraph. No pruning here.

    If ``app_packages`` is None or empty, auto-detect from the JSON via
    :func:`auto_detect_app_packages`.
    """
    raw = json.loads(Path(json_path).read_text(encoding="utf-8"))
    if not app_packages:
        app_packages = auto_detect_app_packages(raw)
    app_pkgs = frozenset(app_packages)

    nodes: dict[str, FunctionNode] = {}
    edges: list[CallEdge] = []

    def add(qn: str) -> None:
        if qn and qn not in nodes:
            nodes[qn] = FunctionNode(qname=qn, kind=classify(qn, app_pkgs))

    for caller, callees in raw.items():
        if not caller:
            continue
        # Skip module-level entries like {"server": ["server.main"]}.
        # JARVIS emits these to say "the module exports main", but it is
        # not an actual function call — keeping it would create a fake
        # caller "server" with no real meaning.
        if caller in app_pkgs and "." not in caller:
            continue
        add(caller)
        for callee in callees:
            if not callee:
                continue
            add(callee)
            edges.append(CallEdge(caller=caller, callee=callee))

    return CallGraph(nodes=nodes, edges=edges, project_id=project_id)


def detect_entries(
    cg: CallGraph,
    app_packages: set[str] | frozenset[str],
) -> CallGraph:
    """Return a new CallGraph with is_entry set on candidate entry points.

    Heuristic: any APP function whose qname has exactly 2 segments and
    the second segment starts with a lowercase letter (Python convention
    for function names; uppercase indicates a class).
    """
    new_nodes: dict[str, FunctionNode] = {}
    for qn, n in cg.nodes.items():
        is_entry = False
        if n.kind == FuncKind.APP:
            parts = qn.split(".")
            if len(parts) == 2 and parts[1][:1].islower():
                is_entry = True
        new_nodes[qn] = replace(n, is_entry=is_entry)
    return CallGraph(nodes=new_nodes, edges=cg.edges, project_id=cg.project_id)


DEFAULT_DROP_KINDS: frozenset[FuncKind] = frozenset({
    FuncKind.BUILTIN,
    FuncKind.TYPE_METHOD,
    FuncKind.UNRESOLVED,
})


def prune(
    cg: CallGraph,
    *,
    drop_kinds: frozenset[FuncKind] = DEFAULT_DROP_KINDS,
    keep_only_reachable_from_app: bool = True,
) -> CallGraph:
    """Remove noise nodes.

    1. Drop nodes whose kind is in drop_kinds, plus edges touching them.
    2. If keep_only_reachable_from_app, BFS forward from APP nodes and
       keep only nodes reachable from app code (anything else cannot be
       on a vulnerability path that starts at an app entry).
    """
    kept = {qn for qn, n in cg.nodes.items() if n.kind not in drop_kinds}

    adj: dict[str, list[str]] = defaultdict(list)
    for e in cg.edges:
        if e.caller in kept and e.callee in kept:
            adj[e.caller].append(e.callee)

    if keep_only_reachable_from_app:
        reachable = {qn for qn in kept if cg.nodes[qn].kind == FuncKind.APP}
        queue = deque(reachable)
        while queue:
            cur = queue.popleft()
            for nxt in adj[cur]:
                if nxt not in reachable:
                    reachable.add(nxt)
                    queue.append(nxt)
        kept &= reachable

    return CallGraph(
        nodes={qn: cg.nodes[qn] for qn in kept},
        edges=[e for e in cg.edges
               if e.caller in kept and e.callee in kept],
        project_id=cg.project_id,
    )


def _main() -> None:
    if len(sys.argv) < 3:
        print("Usage: jarvis_parser.py <jarvis.json> <app_pkg1,app_pkg2,...>")
        sys.exit(2)

    json_path = Path(sys.argv[1])
    app_pkgs = {p.strip() for p in sys.argv[2].split(",") if p.strip()}

    print(f"Input:        {json_path}")
    print(f"App packages: {sorted(app_pkgs)}")
    print()

    cg_raw = parse_jarvis(json_path, app_pkgs)
    print("[1] Raw parse:")
    for k, v in cg_raw.stats().items():
        print(f"    {k:18s} {v}")

    cg_ent = detect_entries(cg_raw, app_pkgs)
    entries = sorted(n.qname for n in cg_ent.nodes.values() if n.is_entry)
    print(f"\n[2] Detected entries ({len(entries)}):")
    for e in entries:
        print(f"    {e}")

    cg_pruned = prune(cg_ent)
    print("\n[3] After prune (drop builtins/type_methods/unresolved + keep only reachable from app):")
    for k, v in cg_pruned.stats().items():
        print(f"    {k:18s} {v}")

    # Sample edges that cross the app -> tpl boundary
    boundary = [
        e for e in cg_pruned.edges
        if cg_pruned.nodes[e.caller].kind == FuncKind.APP
        and cg_pruned.nodes[e.callee].kind != FuncKind.APP
    ]
    print(f"\n[4] App -> non-app boundary edges ({len(boundary)}):")
    for e in boundary[:20]:
        callee_kind = cg_pruned.nodes[e.callee].kind.value
        print(f"    {e.caller}  ->  [{callee_kind}] {e.callee}")
    if len(boundary) > 20:
        print(f"    ... (+{len(boundary) - 20} more)")


if __name__ == "__main__":
    _main()
