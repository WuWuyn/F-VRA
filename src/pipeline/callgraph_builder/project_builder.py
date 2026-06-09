"""
callgraph_builder.project_builder
═════════════════════════════════
Project-Centered Call Graph construction — the **application** side of the
VRA / PyShare framework, and the producer of the **Usage Index (UI)**.

Where :mod:`callgraph_builder.library_builder` (Phase 1) walks a third-party
library *exhaustively* — every function and method becomes a node whether or not
anything ever calls it — this module (Phase 3) does the opposite. An application
contains a great deal of dead code (unused helpers, disabled feature branches,
vendored snippets), and analysing it wastes time *and* manufactures spurious
cross-TPL edges that never actually fire at runtime. So we build the project's
call graph **lazily**, driven by *reachability*:

    Entry points → worklist → (analyse → discover callees → enqueue) → fixpoint

Only code transitively reachable from a real entry point is ever analysed. The
by-product of that walk is the prize: every time a reachable function crosses the
boundary into another library (``requests.get()``, ``flask.Flask()``), we emit a
precise :class:`~pyshare.core.models.ExternalNode`. The deduplicated set of those
boundary calls **is** the Usage Index ($UI$) — the exact list of third-party
symbols this application actually triggers, which downstream phases intersect
against the per-library summaries to answer "is the app reachable to this CVE?".

The 3-step engine
-----------------
**Step 1 — Global Project Indexing (exhaustive scan).** Reachability is lazy, but
*symbol resolution* cannot be: to know that a call inside file *A* lands on a
class defined in file *B* we must already have indexed *B*. So we first scan
**every** ``.py`` file and build a :class:`ProjectIndex`. This subclasses Phase
1's :class:`~callgraph_builder.library_builder.LibraryIndex` and therefore inherits
its battle-tested machinery *verbatim*: longest-suffix module resolution
(``pkg.mod.Cls`` ↔ ``mod.Cls``), MRO / ``base_classes`` linearisation for
``super()`` and inherited-method dispatch, and internal-vs-external import
classification. On top of that it builds one extra table — a **definition
registry** mapping each canonical :class:`FunctionNode` back to its AST node — so
the worklist can re-open a function for analysis the moment it is popped.

**Step 2 — Entry Point Discovery (:class:`EntryPointDetector`).** Scans the index
for the two strongest static signals of "the outside world calls in here":

    a) ``if __name__ == "__main__":`` guards (each bare call inside resolves to a
       module-level function → :attr:`EntryPointType.MAIN`).
    b) web-framework route decorators whose dotted name starts with one of
       ``@app.`` / ``@router.`` / ``@bp.`` (→ :attr:`EntryPointType.WEB`).

    **Critical fallback:** if *exactly zero* entry points are found (a library-like
    project, or one using a framework we don't pattern-match), we degrade
    gracefully by treating **all module-level public functions** as entry points,
    rather than returning an empty graph.

**Step 3 — Worklist-Driven Analyzer (:class:`WorklistProjectAnalyzer`).** Seeds a
worklist with the discovered entry points and runs to a fixpoint. Each popped
function is analysed with the **exact same 2-layer pipeline as Phase 1** — there
is deliberately *no* second implementation of it here; we import and drive the
real classes:

    * **Layer 1** — :class:`~callgraph_builder.library_builder.ASTCandidateGenerator`
      (broad net / high recall): pure-syntactic tentative edges for every call.
    * **Layer 2** — :class:`~callgraph_builder.library_builder.AndersenPointsToAnalyzer`
      (flow-sensitive points-to with strong updates): prunes Layer 1's
      over-approximation down to the receiver types that can actually reach a site.

Then the orchestration applies the same Layer-2 *refinement* rule as
:class:`~callgraph_builder.library_builder.LibraryAnalyzer` and acts on each
surviving callee:

    * **Internal** target (resolved to a project file) → record the edge and, if
      the function has never been analysed, push it onto the worklist.
    * **External** target (an :class:`ExternalNode`) → record the exact,
      *non-prunable* boundary edge and add it to the Usage Index, **but never
      enqueue it** — we do not own that code and do not walk into it.

Output
------
:func:`build_project_graph` returns ``Tuple[CallGraph, List[ExternalNode]]``:
the reachable internal call graph, and the Usage Index (deduplicated boundary
calls). :func:`build_application_centered_graph` is retained as a thin
backward-compatible wrapper (caller supplies its own entry points; returns just
the :class:`CallGraph`).

Robustness contract (identical to Phase 1)
------------------------------------------
  * **Never execute project code** — 100 % static ``ast`` parsing.
  * **Never crash on bad input** — sources are read ``utf-8-sig`` and every parse
    / per-function analysis is wrapped so one broken module can't abort the build.
  * **Reuse, don't reinvent** — Layer 1, Layer 2, the index, MRO/``super()``
    handling and :class:`PointsToState` semantics are imported from
    ``library_builder``; only the entry-point discovery and the
    reachability-driven worklist are new here.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pyshare.core.models import (
    CallEdge,
    CallGraph,
    EntryPointType,
    ExternalNode,
    FunctionNode,
)

# ── Reuse Phase 1 verbatim — do NOT reimplement the index or either layer. ──────
# These are the precise, perfected building blocks from ``library_builder``:
#   * LibraryIndex                  — exhaustive symbol table + MRO + suffix lookup
#   * ModuleScope / ClassInfo       — per-file resolution context
#   * ASTCandidateGenerator (L1)    — broad-net candidate generation (incl. super())
#   * AndersenPointsToAnalyzer (L2) — flow-sensitive points-to / strong updates
#   * Candidate / PointsToSet       — the data carried between the two layers
from pyshare.pipeline.callgraph_builder.library_builder import (  # noqa: F401
    ASTCandidateGenerator,
    AndersenPointsToAnalyzer,
    Candidate,
    ClassInfo,
    LibraryIndex,
    ModuleScope,
    PointsToSet,
    _FuncDef,
    _dotted_name,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# STEP 1 — GLOBAL PROJECT INDEX (exhaustive scan, lazy analysis)
# ══════════════════════════════════════════════════════════════════

@dataclass
class _DefContext:
    """Everything the worklist needs to (re-)analyse one function on demand.

    Captured once during indexing so that, when a :class:`FunctionNode` is popped
    off the worklist, we can immediately re-open its body without re-walking the
    whole tree: the AST def node to analyse, the :class:`ModuleScope` that resolves
    its names, and (for methods) the :class:`ClassInfo` that owns it so ``self`` /
    ``cls`` / ``super()`` resolve through the right MRO.
    """
    def_node: _FuncDef
    scope: ModuleScope
    enclosing: Optional[ClassInfo]


class ProjectIndex(LibraryIndex):
    """Exhaustive whole-project symbol table + a function→AST definition registry.

    Inherits *all* of :class:`~callgraph_builder.library_builder.LibraryIndex`'s
    behaviour unchanged — the filesystem walk, ``utf-8-sig`` safe parsing,
    longest-suffix class/function resolution, internal-vs-external import
    classification, and the MRO machinery (:meth:`iter_bases`,
    :meth:`mro_classes`, :meth:`resolve_method_mro`) that powers ``super()`` and
    inherited-method dispatch. We add exactly one thing the worklist needs that an
    exhaustive builder does not: a :attr:`def_registry` mapping every canonical
    :class:`FunctionNode` to its :class:`_DefContext`, so a popped node can be
    re-opened for analysis in O(1).

    The registry is keyed by :class:`FunctionNode` identity ``(normpath, name)``
    — methods carry ``"Class.method"`` names (set by the base index), so a fresh
    node built by the entry-point detector with the same file+name still hits the
    canonical context here.
    """

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        # FunctionNode -> how to analyse it. Populated after the base two passes.
        self.def_registry: Dict[FunctionNode, _DefContext] = {}

    def build(self) -> "ProjectIndex":
        super().build()                 # pass 1 (collect) + pass 2 (scopes)
        self._build_def_registry()      # pass 3: function -> AST def context
        logger.info("[ProjGraph] Project index ready: %d definition(s) registered",
                    len(self.def_registry))
        return self

    def _build_def_registry(self) -> None:
        """Map each canonical module-level function and direct method to its AST.

        Mirrors :meth:`LibraryAnalyzer._iter_defs` so the *same* canonical nodes
        the index already minted (``scope.local_funcs`` / ``ClassInfo.methods``)
        become the registry keys — guaranteeing the worklist, the candidate
        generator and the edges all share one node identity per function.
        """
        for path, tree in self.asts.items():
            scope = self.scopes.get(path)
            if scope is None:
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = scope.local_funcs.get(node.name)
                    if fn is not None:
                        self.def_registry[fn] = _DefContext(node, scope, None)
                elif isinstance(node, ast.ClassDef):
                    ci = scope.local_classes.get(node.name)
                    if ci is None:
                        continue
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            mnode = ci.methods.get(sub.name)
                            if mnode is not None:
                                self.def_registry[mnode] = _DefContext(sub, scope, ci)


# ══════════════════════════════════════════════════════════════════
# STEP 2 — ENTRY POINT DISCOVERY
# ══════════════════════════════════════════════════════════════════

# A web route decorator's *head* — the object the decorator hangs off. Flask's
# ``@app.route`` / ``@bp.route``, FastAPI/Starlette's ``@app.get`` /
# ``@router.post`` all attach the verb to one of these well-known names. We match
# on the head rather than the verb so any HTTP method (or a custom one) counts,
# exactly as the task specifies ("node names starting with @app./@router./@bp.").
WEB_DECORATOR_HEADS: Set[str] = {"app", "router", "bp", "blueprint", "api"}


def _is_main_guard(test: ast.expr) -> bool:
    """``True`` for an ``if __name__ == "__main__":`` test (either operand order).

    Mirrors ``project_scanner.scanner._is_main_guard`` so entry-point detection is
    consistent with the standalone scanner.
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    return (_eq_name_str(left, right) or _eq_name_str(right, left))


def _eq_name_str(name_side: ast.expr, str_side: ast.expr) -> bool:
    return (isinstance(name_side, ast.Name) and name_side.id == "__name__"
            and isinstance(str_side, ast.Constant) and str_side.value == "__main__")


def _decorator_dotted(dec: ast.expr) -> Optional[str]:
    """Dotted name of a decorator, unwrapping a decorator-factory call.

    ``@app.route("/")`` → ``"app.route"``; ``@router.get`` → ``"router.get"``;
    ``@staticmethod`` → ``"staticmethod"``. Returns ``None`` for shapes we can't
    flatten (subscripted / dynamically-built decorators).
    """
    target = dec.func if isinstance(dec, ast.Call) else dec
    return _dotted_name(target)


def _is_web_route_decorator(dec: ast.expr) -> bool:
    """Whether *dec* looks like a web route binding (``@app.`` / ``@router.`` …)."""
    dotted = _decorator_dotted(dec)
    if not dotted or "." not in dotted:
        return False
    return dotted.split(".", 1)[0] in WEB_DECORATOR_HEADS


class EntryPointDetector:
    """Discover application entry points from an already-built :class:`ProjectIndex`.

    Two positive signals, then a safety net:

      a) **``__main__`` guards** — every bare ``name()`` called inside an
         ``if __name__ == "__main__":`` block that resolves to a module-level
         function in the same file (``EntryPointType.MAIN``).
      b) **Web route decorators** — any function or method decorated with
         ``@app.* / @router.* / @bp.*`` (``EntryPointType.WEB``).

      **Fallback** — if (a) and (b) together yield *nothing*, return **all
      module-level public functions** (name not starting with ``_``) so a
      library-style or unrecognised-framework project still produces a usable,
      non-empty reachable graph instead of an empty one.

    Returned nodes are the index's *canonical* :class:`FunctionNode` objects (so
    their identity matches everything the worklist will discover later), with
    their :attr:`entry_type` stamped to reflect *why* they were chosen.
    """

    def __init__(self, index: ProjectIndex) -> None:
        self.index = index

    def detect(self) -> List[FunctionNode]:
        found: Dict[FunctionNode, EntryPointType] = {}

        for path, tree in self.index.asts.items():
            scope = self.index.scopes.get(path)
            if scope is None:
                continue
            try:
                self._scan_main_guards(tree, scope, found)
                self._scan_decorated_defs(tree, scope, found)
            except Exception as exc:    # one odd module never aborts discovery
                logger.debug("[ProjGraph] entry-point scan error in %s: %s", path, exc)

        if found:
            entries = self._stamp(found)
            logger.info("[ProjGraph] Discovered %d entry point(s) "
                        "(%d main, %d web)", len(entries),
                        sum(t is EntryPointType.MAIN for t in found.values()),
                        sum(t is EntryPointType.WEB for t in found.values()))
            return entries

        # ── CRITICAL FALLBACK ──────────────────────────────────────────────
        # No explicit entry signal anywhere → treat every module-level public
        # function as a possible entry, so the worklist still has something to
        # walk from. Better an over-approximate reachable set than an empty one.
        fallback = self._fallback_public_functions()
        logger.warning("[ProjGraph] No explicit entry points found; falling back "
                       "to %d module-level public function(s)", len(fallback))
        return fallback

    # -- signal (a): __main__ guards ------------------------------

    def _scan_main_guards(self, tree: ast.Module, scope: ModuleScope,
                          found: Dict[FunctionNode, EntryPointType]) -> None:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.If) and _is_main_guard(node.test)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    fn = scope.local_funcs.get(sub.func.id)
                    if fn is not None:
                        found.setdefault(fn, EntryPointType.MAIN)

    # -- signal (b): web route decorators -------------------------

    def _scan_decorated_defs(self, tree: ast.Module, scope: ModuleScope,
                             found: Dict[FunctionNode, EntryPointType]) -> None:
        # Module-level functions decorated as routes.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._has_web_decorator(node):
                    fn = scope.local_funcs.get(node.name)
                    if fn is not None:
                        found.setdefault(fn, EntryPointType.WEB)
            elif isinstance(node, ast.ClassDef):
                # Class-based views: decorated methods are routes too.
                ci = scope.local_classes.get(node.name)
                if ci is None:
                    continue
                for sub in node.body:
                    if (isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and self._has_web_decorator(sub)):
                        meth = ci.methods.get(sub.name)
                        if meth is not None:
                            found.setdefault(meth, EntryPointType.WEB)

    @staticmethod
    def _has_web_decorator(node: _FuncDef) -> bool:
        return any(_is_web_route_decorator(dec) for dec in node.decorator_list)

    # -- fallback: all module-level public functions --------------

    def _fallback_public_functions(self) -> List[FunctionNode]:
        out: List[FunctionNode] = []
        seen: Set[FunctionNode] = set()
        for scope in self.index.scopes.values():
            for name, fn in scope.local_funcs.items():
                if name.startswith("_"):
                    continue
                if fn not in seen:
                    seen.add(fn)
                    fn.entry_type = EntryPointType.UNKNOWN
                    out.append(fn)
        return out

    @staticmethod
    def _stamp(found: Dict[FunctionNode, EntryPointType]) -> List[FunctionNode]:
        """Stamp the discovered reason onto each canonical node and return them."""
        entries: List[FunctionNode] = []
        for fn, etype in found.items():
            fn.entry_type = etype
            entries.append(fn)
        return entries


# ══════════════════════════════════════════════════════════════════
# STEP 3 — WORKLIST-DRIVEN ANALYZER (reachability-driven, lazy)
# ══════════════════════════════════════════════════════════════════

class WorklistProjectAnalyzer:
    """Reachability-driven call-graph construction + Usage Index extraction.

    Seeds a worklist with the entry points and runs a classic fixpoint: pop a
    function, analyse it with the imported Phase-1 2-layer pipeline, record the
    resolved edges, enqueue every *internal* callee never seen before, and emit an
    :class:`ExternalNode` for every *external* callee (without enqueueing it).
    When the worklist drains, the reachable internal graph and the deduplicated
    Usage Index are complete.
    """

    def __init__(self, index: ProjectIndex) -> None:
        self.index = index
        self.graph = CallGraph()
        self.worklist: List[FunctionNode] = []
        self._seen_edges: Set[Tuple[FunctionNode, FunctionNode]] = set()
        # Usage Index ($UI$): deduplicated boundary calls, keyed by ExternalNode
        # identity (target_module, target_name) so the same symbol called from
        # many sites collapses to one entry.
        self._external: Dict[ExternalNode, ExternalNode] = {}

    # -- public driver --------------------------------------------

    def run(self, entry_points: List[FunctionNode]) -> Tuple[CallGraph, List[ExternalNode]]:
        # Seed the worklist; entry points become the graph's roots.
        for ep in entry_points:
            if self.graph.add_node(ep):
                self.worklist.append(ep)

        # Fixpoint: each internal node is enqueued (and thus analysed) at most
        # once, because we only enqueue on a *newly inserted* node.
        while self.worklist:
            caller = self.worklist.pop()
            try:
                callees = self._analyze(caller)
            except Exception as exc:    # a single bad function never kills the build
                logger.warning("[ProjGraph] Failed to analyze %s (%s): %s",
                               caller.function_name, caller.file_path, exc)
                continue
            for callee in callees:
                self._record(caller, callee)

        ui = list(self._external.values())
        logger.info("[ProjGraph] Reachable graph: %d node(s), %d edge(s); "
                    "Usage Index: %d external symbol(s)",
                    len(self.graph.nodes), len(self.graph.edges), len(ui))
        return self.graph, ui

    # -- edge / node bookkeeping ----------------------------------

    def _record(self, caller: FunctionNode, callee: FunctionNode) -> None:
        """Record one resolved edge and route the callee by internal/external."""
        edge_key = (caller, callee)
        if edge_key not in self._seen_edges:
            self._seen_edges.add(edge_key)
            self.graph.edges.append(CallEdge(caller=caller, callee=callee))

        if callee.is_external:
            # Cross-TPL boundary: contribute to the Usage Index, keep the node in
            # the graph so the boundary edge is well-formed, but NEVER walk into
            # it — we do not own that library's source.
            assert isinstance(callee, ExternalNode)
            self._external.setdefault(callee, callee)
            self.graph.add_node(callee)
        else:
            # Internal project function: enqueue it the first time we see it.
            if self.graph.add_node(callee):
                self.worklist.append(callee)

    # -- per-function analysis (Layer 1 → Layer 2 → refine) -------

    def _analyze(self, caller: FunctionNode) -> List[FunctionNode]:
        """Run the exact Phase-1 2-layer pipeline over one reachable function.

        Identical staging to :meth:`LibraryAnalyzer._analyze_definition`: Layer 1
        emits broad candidates per call site (with ``super()`` resolved through the
        enclosing class's MRO), Layer 2 computes flow-sensitive receiver types, and
        :meth:`_refine` prunes Layer 1 down to what Layer 2 confirms.
        """
        ctx = self.index.def_registry.get(caller)
        if ctx is None:
            # Caller has no body we can open (e.g. an external node accidentally
            # enqueued, or a node minted outside the index). Nothing to analyse.
            return []

        # Layer 1: broad-net tentative edges, keyed by call site.
        sites = ASTCandidateGenerator(self.index, ctx.scope,
                                      ctx.enclosing).generate(ctx.def_node)
        if not sites:
            return []
        # Layer 2: flow-sensitive points-to → receiver type at each call site.
        pt = AndersenPointsToAnalyzer(self.index, ctx.scope,
                                      ctx.enclosing).compute(ctx.def_node)

        callees: List[FunctionNode] = []
        for site_id, cands in sites.items():
            callees.extend(self._refine(cands, pt.get(site_id)))
        return callees

    def _refine(self, cands: List[Candidate],
                receiver_pt: Optional[PointsToSet]) -> List[FunctionNode]:
        """Apply Layer-2 judgement to one call site's Layer-1 candidates.

        Faithfully mirrors :meth:`LibraryAnalyzer._refine` — the orchestration glue
        that turns points-to facts into kept/pruned edges:

          * non-prunable candidates (direct calls, constructors, ``super()`` and
            **external boundary edges**) are always kept;
          * if the receiver type is *top* (unknown), static pruning is unsafe, so
            we defer to the LLM oracle and, when it abstains, keep the full broad
            net to preserve recall;
          * if the receiver type is *concrete*, only candidates whose owning class
            is in the points-to set survive — and a known-but-unmatched receiver
            (a stdlib/3rd-party object) gets one last shot at the oracle.
        """
        keep: List[FunctionNode] = [c.callee for c in cands if not c.prunable]
        prunable = [c for c in cands if c.prunable]
        if not prunable:
            return keep

        call_node = prunable[0].call_node

        if receiver_pt is None:
            resolved = self._resolve_with_llm(call_node)
            if resolved is not None:
                keep.append(resolved)
            else:
                keep.extend(c.callee for c in prunable)
            return keep

        matched = [c.callee for c in prunable if c.owner in receiver_pt]
        if matched:
            keep.extend(matched)
        else:
            resolved = self._resolve_with_llm(call_node)
            if resolved is not None:
                keep.append(resolved)
        return keep

    def _resolve_with_llm(self, call_node: ast.Call) -> Optional[FunctionNode]:
        """Placeholder for the future LLM disambiguation oracle (see Phase 1).

        A deliberate no-op for this iteration: genuinely dynamic dispatch
        (``getattr(obj, name)()``, factory returns, reflective ``__getattr__``)
        falls back to "keep the broad net" rather than being guessed. The real
        prompt construction lands in a later phase, identically to
        :meth:`LibraryAnalyzer._resolve_with_llm`.
        """
        return None


# ══════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ══════════════════════════════════════════════════════════════════

def build_project_graph(project_root: Path) -> Tuple[CallGraph, List[ExternalNode]]:
    """Build the reachable project call graph and its Usage Index ($UI$).

    Runs the full 3-step engine: exhaustive indexing → entry-point discovery →
    reachability-driven worklist analysis.

    Parameters
    ----------
    project_root:
        Root directory of the target application to analyse.

    Returns
    -------
    Tuple[CallGraph, List[ExternalNode]]
        * **CallGraph** — the reachable internal call graph: ``nodes`` = every
          project function transitively reachable from an entry point (plus the
          external boundary nodes that those calls land on), ``edges`` = the
          points-to-refined call relationships between them.
        * **List[ExternalNode]** — the **Usage Index**: the deduplicated set of
          exact cross-TPL boundary calls the application actually triggers.

    Raises
    ------
    FileNotFoundError / NotADirectoryError
        If *project_root* does not exist or is not a directory. Unreadable or
        unparsable individual modules are skipped, never fatal.
    """
    root = Path(project_root)
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")

    # Step 1 — exhaustive index (symbol resolution must be complete & eager).
    index = ProjectIndex(root).build()
    # Step 2 — discover where the outside world calls in (with safe fallback).
    entry_points = EntryPointDetector(index).detect()
    # Step 3 — lazily walk only what those entry points can reach.
    return WorklistProjectAnalyzer(index).run(entry_points)


def build_application_centered_graph(
    entry_points: List[FunctionNode], project_root: Path
) -> CallGraph:
    """Backward-compatible wrapper: build the reachable graph from *given* entries.

    Retained for callers (e.g. the legacy JARVIS driver / ``test_builder.py``) that
    run entry-point discovery themselves via ``project_scanner.scan_project`` and
    pass the result in. It runs the same reachability-driven worklist over the same
    2-layer pipeline as :func:`build_project_graph`, but skips internal entry-point
    discovery and returns only the :class:`CallGraph` (callers that also want the
    Usage Index should prefer :func:`build_project_graph`).

    Parameters
    ----------
    entry_points:
        Seed functions to start the worklist from — typically the output of
        ``project_scanner.scan_project``. An empty list yields an empty graph.
    project_root:
        Root directory of the target project; only functions defined under it are
        resolved and walked.
    """
    root = Path(project_root)
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")

    index = ProjectIndex(root).build()
    # Re-key the caller-supplied entry points onto the index's canonical nodes
    # where possible, so identity matches everything the worklist discovers; any
    # node not in the registry is still usable as a seed (it simply analyses to
    # no callees if it has no resolvable body).
    seeds: List[FunctionNode] = []
    seen: Set[FunctionNode] = set()
    registry = index.def_registry
    for ep in entry_points:
        canonical = next((fn for fn in registry if fn == ep), ep)
        if canonical not in seen:
            seen.add(canonical)
            seeds.append(canonical)

    graph, _ui = WorklistProjectAnalyzer(index).run(seeds)
    return graph
