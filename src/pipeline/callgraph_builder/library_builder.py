"""
callgraph_builder.library_builder
══════════════════════════════════
Library-Centered Call Graph construction — the **G_L** (library call graph)
side of the VRA / PyShare framework.

Where ``project_builder`` walks *outward from application entry points* (lazy,
reachability-driven), this module does the opposite: it **exhaustively** scans an
entire third-party library (TPL) and reconstructs the most precise call graph it
can for *every* function and method the library defines. That graph later lets us
ask "does a vulnerable library function lie on a path reachable from the API the
application actually calls?".

Two cooperating layers implement the engine — a *generate-then-prune* pipeline:

  * **Layer 1 — :class:`ASTCandidateGenerator` (broad net / high recall).**
    Pure-syntactic. For a call ``x.m()`` it knows nothing about the type of ``x``,
    so it conservatively emits a *tentative* edge to **every** in-scope class that
    defines a method named ``m``. This over-approximates: recall is ~100 %, but
    precision is poor (many spurious edges).

  * **Layer 2 — :class:`AndersenPointsToAnalyzer` (fine filter / flow-sensitive).**
    The "brain". It re-walks each function maintaining a flow-sensitive
    :class:`PointsToState` (``pt(x) = {TypeA, TypeB}``) and applies **strong
    updates** on unconditional assignments (``x = Dog()`` ⇒ ``pt(x) = {Dog}``,
    *overwriting* — not merging — any prior binding). At each call site it uses
    the points-to set of the receiver to **prune** the spurious Layer-1 edges:
    if ``pt(x) = {Dog}`` then the tentative edge to ``Cat.m`` is dropped.

  * **Orchestrator — :class:`LibraryAnalyzer`.** Builds a whole-library index,
    drives Layer 1 then Layer 2 over every definition, and assembles the final
    :class:`~pyshare.core.models.CallGraph`. It also hosts the future
    :meth:`LibraryAnalyzer._resolve_with_llm` oracle hook (a no-op stub for now)
    that will eventually disambiguate genuinely dynamic dispatch (``getattr`` &
    friends) that neither static layer can resolve.

Hard rules for this engine (same robustness contract as ``project_builder``):
  * **Never execute library code.** Analysis is 100 % static ``ast`` parsing.
  * **Never crash on bad input.** Third-party code is read with ``utf-8-sig`` and
    every parse / per-definition analysis is wrapped so one unreadable or
    syntactically-broken module can never abort the whole build.
  * **Reuse the core models** (:class:`FunctionNode`, :class:`CallEdge`,
    :class:`CallGraph`) rather than inventing parallel ones.

Identity note
-------------
``FunctionNode`` identity is ``(normpath(file_path), function_name)``. A single
library file routinely defines many same-named methods (``Dog.run`` and
``Cat.run`` in one module), so for **methods** this engine sets
``function_name = "Class.method"`` (e.g. ``"Dog.run"``) to keep their identities
distinct, while ``qualified_name`` carries the full dotted path
(``pkg.mod.Dog.run``). Module-level functions keep their bare name. This is a
deliberate, documented divergence from ``project_builder`` (which deals in bare
names because it resolves one reachable target at a time).
"""
from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union

from pyshare.core.models import (
    CallEdge,
    CallGraph,
    EntryPointType,
    ExternalNode,
    FunctionNode,
)

logger = logging.getLogger(__name__)

PathLike = Union[str, "os.PathLike[str]"]

# Subtrees that never hold the library's own first-party source. We still scan a
# library exhaustively, but we skip vendored deps / build artefacts / caches so
# the graph reflects *this* library rather than everything bundled beside it.
IGNORE_DIRS = {
    "venv", "env", "virtualenv", "__pycache__", "node_modules",
    "site-packages", "build", "dist", ".tox", ".eggs", "tests", "test",
}

_FuncDef = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# A points-to set is the set of (fully-qualified) class names a variable may
# refer to at a given program point. The empty / absent state means "top":
# unknown — could be anything (so Layer 2 must not prune on it).
PointsToSet = Set[str]
PointsToState = Dict[str, PointsToSet]


# ══════════════════════════════════════════════════════════════════
# SAFE PARSING  (third-party code is hostile to assumptions)
# ══════════════════════════════════════════════════════════════════

def _safe_parse(path: Path) -> Optional[ast.Module]:
    """Parse *path* with ``ast``; return ``None`` (and log) on any failure.

    Mirrors ``project_builder._safe_parse`` — uses ``utf-8-sig`` so BOM-prefixed
    sources read cleanly, and swallows every failure mode a random TPL file can
    throw (unreadable, wrong encoding, null bytes, syntax error, pathological
    nesting) so the exhaustive scan never aborts mid-library.
    """
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("[LibGraph] Cannot read %s: %s", path, exc)
        return None

    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        logger.warning("[LibGraph] Skipping %s (syntax error: %s)", path, exc)
        return None
    except (ValueError, RecursionError) as exc:
        # ValueError: null bytes in source; RecursionError: pathological nesting.
        logger.warning("[LibGraph] Skipping %s (parse failure: %s)", path, exc)
        return None


# ══════════════════════════════════════════════════════════════════
# INDEX DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════

@dataclass
class ClassInfo:
    """A class discovered in the library and the methods it directly defines.

    ``methods`` maps a method's *simple* name (``run``) to the prebuilt
    :class:`FunctionNode` for it, so candidate generation and the worklist share
    one canonical node per method (identity stays consistent across call sites).

    ``base_classes`` holds the parent classes *as written* in the ``ClassDef``
    bases (e.g. ``"Base"`` or ``"animals.Base"``). They are stored raw because a
    base name can only be resolved to a concrete :class:`ClassInfo` once the
    *whole* library is indexed and the child's import scope is known — that
    resolution happens lazily in :meth:`LibraryIndex.iter_bases`.
    """
    name: str                                   # simple name, e.g. "Dog"
    qualified: str                              # dotted, e.g. "pkg.animals.Dog"
    file_path: Path
    methods: Dict[str, FunctionNode] = field(default_factory=dict)
    base_classes: List[str] = field(default_factory=list)   # parent names as written


@dataclass
class ModuleScope:
    """Everything visible *inside one source file* that we can resolve a call to.

    Built in a second pass once every class/function in the library is known, so
    imports can be resolved to first-party :class:`ClassInfo` / :class:`FunctionNode`
    objects. Third-party / stdlib imports simply fail to resolve and are ignored.
    """
    file_path: Path
    module_dotted: str
    # Classes visible by the name used in *this* file (local defs + imported).
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    # Classes physically defined in this file (used to iterate own methods).
    local_classes: Dict[str, ClassInfo] = field(default_factory=dict)
    # Module-level functions defined in this file.
    local_funcs: Dict[str, FunctionNode] = field(default_factory=dict)
    # Functions pulled in by ``from mod import func``.
    imported_funcs: Dict[str, FunctionNode] = field(default_factory=dict)
    # Module aliases for ``import a.b as m`` / ``import a`` -> dotted module path,
    # enabling ``m.func()`` and ``m.Class()`` resolution.
    module_aliases: Dict[str, str] = field(default_factory=dict)
    # ── Cross-TPL boundary tracking ────────────────────────────────────────
    # External (third-party / stdlib) module aliases that do NOT resolve to this
    # library's own source: bound name -> external dotted module. Drives
    # ``requests.get()`` / ``serving.run_simple()`` to ExternalNode edges.
    external_modules: Dict[str, str] = field(default_factory=dict)
    # External symbols imported via ``from mod import sym``: bound name ->
    # (external module, symbol). Drives a bare ``sym()`` to an ExternalNode edge.
    external_funcs: Dict[str, Tuple[str, str]] = field(default_factory=dict)


@dataclass
class Candidate:
    """One tentative call edge emitted by Layer 1, awaiting Layer-2 judgement.

    ``prunable`` marks edges that Layer 2 may filter using points-to (i.e. the
    ``x.m()`` method-dispatch edges). Direct function / constructor calls have a
    single statically-known target, so ``prunable=False`` keeps them verbatim.
    """
    callee: FunctionNode
    owner: Optional[str]            # qualified class owning the method (prunable edges)
    base_var: Optional[str]        # receiver variable name in ``x.m()`` (else None)
    call_node: ast.Call
    prunable: bool


def _dotted_name(expr: ast.expr) -> Optional[str]:
    """Flatten a ``Name`` / ``Attribute`` chain to a dotted string, else ``None``.

    ``Base`` -> ``"Base"``; ``animals.Base`` -> ``"animals.Base"``. Complex base
    expressions (``Generic[T]``, ``mixin_factory()``) flatten to ``None`` and are
    simply not treated as resolvable parent classes.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        head = _dotted_name(expr.value)
        return f"{head}.{expr.attr}" if head else None
    return None


def _make_external_node(module: str, name: str, line: int = 0) -> ExternalNode:
    """Build the boundary marker for a statically-known call into another library.

    External targets are *exact* (the symbol was explicitly imported), so the
    resulting :class:`ExternalNode` is always emitted as a non-prunable edge —
    Layer 2 (Andersen) never needs to second-guess it.
    """
    qualified = ".".join(p for p in (module, name) if p)
    return ExternalNode(
        file_path=f"<external:{module or '?'}>",
        function_name=qualified,
        qualified_name=qualified,
        line_number=line,
        entry_type=EntryPointType.UNKNOWN,
        target_module=module,
        target_name=name,
    )


# ══════════════════════════════════════════════════════════════════
# LIBRARY INDEX  — exhaustive whole-library symbol table
# ══════════════════════════════════════════════════════════════════

class LibraryIndex:
    """Scan *every* ``.py`` file under the library root and build symbol tables.

    Produces:
      * one :class:`ClassInfo` per class (with its methods as canonical nodes),
      * one :class:`FunctionNode` per module-level function,
      * **longest-suffix** lookup tables (``class_suffix`` / ``func_suffix``) that
        map any dotted import path to the right symbol regardless of how the
        library is rooted (``requests.sessions.Session`` ↔ ``sessions.Session``),
      * a per-file :class:`ModuleScope` resolving the file's imports.

    Suffix collisions (two different symbols sharing a tail) are *dropped* rather
    than guessed, exactly like ``project_builder._ProjectIndex``.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.asts: Dict[Path, ast.Module] = {}
        self.classes: List[ClassInfo] = []
        self.functions: List[FunctionNode] = []
        self.public_api: List[FunctionNode] = []
        self.scopes: Dict[Path, ModuleScope] = {}
        # All dotted suffixes of every first-party module — lets us tell a
        # library-internal import apart from a third-party / stdlib one
        # regardless of how the library is rooted (``requests.sessions`` ↔
        # ``sessions``). Anything that matches none of these is *external*.
        self.internal_module_suffixes: Set[str] = set()

        # suffix -> (qualified, value); ambiguous suffixes are removed entirely.
        self._class_suffix: Dict[str, Tuple[str, ClassInfo]] = {}
        self._func_suffix: Dict[str, Tuple[str, FunctionNode]] = {}
        self._class_ambig: Set[str] = set()
        self._func_ambig: Set[str] = set()

    # -- public build entry ---------------------------------------

    def build(self) -> "LibraryIndex":
        # Pass 1: collect every class / function and their AST.
        for path in self._iter_py_files():
            tree = _safe_parse(path)
            if tree is None:
                continue
            self.asts[path] = tree
            self._register_module_suffixes(self.module_dotted(path))
            self._collect_definitions(path, tree)
        # Pass 2: now that all symbols exist, resolve each file's imports.
        for path, tree in self.asts.items():
            self.scopes[path] = self._build_scope(path, tree)
        logger.info("[LibGraph] Indexed %d class(es), %d function(s) across %d file(s)",
                    len(self.classes), len(self.functions), len(self.asts))
        return self

    # -- filesystem walk ------------------------------------------

    def _iter_py_files(self) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in IGNORE_DIRS]
            for name in filenames:
                if name.endswith(".py"):
                    yield Path(dirpath) / name

    def module_dotted(self, path: Path) -> str:
        """Dotted module name of *path* relative to the root (``__init__`` dropped)."""
        try:
            rel = path.resolve().relative_to(self.root)
        except ValueError:
            return path.stem
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _register_module_suffixes(self, dotted: str) -> None:
        """Record every dotted suffix of an internal module for later lookup."""
        if not dotted:
            return
        parts = dotted.split(".")
        for i in range(len(parts)):
            self.internal_module_suffixes.add(".".join(parts[i:]))

    def is_internal_module(self, dotted: str) -> bool:
        """``True`` iff *dotted* names a module belonging to *this* library.

        Uses longest-suffix matching so an absolute self-import
        (``requests.sessions``) still matches an internally-rooted module
        (``sessions``). A miss means the import crosses the TPL boundary and must
        be recorded as external rather than dropped.
        """
        if not dotted:
            return False
        parts = [p for p in dotted.split(".") if p]
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.internal_module_suffixes:
                return True
        return False

    # -- pass 1: definition collection ----------------------------

    def _collect_definitions(self, path: Path, tree: ast.Module) -> None:
        mod = self.module_dotted(path)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = self._make_func_node(path, node.name, node.name,
                                          self._join(mod, node.name), node.lineno)
                self.functions.append(fn)
                self._index_func(fn)
                if not node.name.startswith("_"):
                    self.public_api.append(fn)
            elif isinstance(node, ast.ClassDef):
                self._collect_class(path, mod, node)

    def _collect_class(self, path: Path, mod: str, cls: ast.ClassDef) -> None:
        qualified = self._join(mod, cls.name)
        bases = [name for name in (_dotted_name(b) for b in cls.bases) if name]
        info = ClassInfo(name=cls.name, qualified=qualified, file_path=path,
                         base_classes=bases)
        for sub in cls.body:
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # function_name carries the class to keep node identity unique
                # within a file; qualified_name carries the full dotted path.
                node = self._make_func_node(
                    path,
                    function_name=f"{cls.name}.{sub.name}",
                    method_name=sub.name,
                    qualified=self._join(qualified, sub.name),
                    line=sub.lineno,
                )
                info.methods.setdefault(sub.name, node)
                self.functions.append(node)
                if not sub.name.startswith("_") or sub.name == "__init__":
                    self.public_api.append(node)
        self.classes.append(info)
        self._index_class(info)

    @staticmethod
    def _make_func_node(path: Path, function_name: str, method_name: str,
                        qualified: str, line: int) -> FunctionNode:
        return FunctionNode(
            file_path=str(path),
            function_name=function_name,
            qualified_name=qualified,
            line_number=line,
            entry_type=EntryPointType.UNKNOWN,
        )

    @staticmethod
    def _join(*parts: str) -> str:
        return ".".join(p for p in parts if p)

    # -- suffix index maintenance ---------------------------------

    def _index_class(self, info: ClassInfo) -> None:
        self._index_suffixes(self._class_suffix, self._class_ambig,
                             info.qualified, info)

    def _index_func(self, fn: FunctionNode) -> None:
        self._index_suffixes(self._func_suffix, self._func_ambig,
                             fn.qualified_name, fn)

    @staticmethod
    def _index_suffixes(table: Dict[str, Tuple[str, object]], ambig: Set[str],
                        qualified: str, value: object) -> None:
        parts = qualified.split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if not suffix or suffix in ambig:
                continue
            existing = table.get(suffix)
            if existing is not None and existing[0] != qualified:
                # Same tail, different symbol -> ambiguous, drop it.
                table.pop(suffix, None)
                ambig.add(suffix)
            else:
                table[suffix] = (qualified, value)

    # -- dotted -> symbol resolution ------------------------------

    def resolve_class_dotted(self, dotted: str) -> Optional[ClassInfo]:
        return self._resolve_suffix(self._class_suffix, dotted)  # type: ignore[return-value]

    def resolve_func_dotted(self, dotted: str) -> Optional[FunctionNode]:
        return self._resolve_suffix(self._func_suffix, dotted)  # type: ignore[return-value]

    @staticmethod
    def _resolve_suffix(table: Dict[str, Tuple[str, object]],
                        dotted: str) -> Optional[object]:
        parts = [p for p in dotted.split(".") if p]
        for i in range(len(parts)):                 # longest suffix first
            hit = table.get(".".join(parts[i:]))
            if hit is not None:
                return hit[1]
        return None

    # -- inheritance / MRO resolution -----------------------------

    def _resolve_base_name(self, scope: Optional["ModuleScope"],
                           name: str) -> Optional[ClassInfo]:
        """Resolve a raw base-class name to its :class:`ClassInfo`.

        Resolution is performed in the *child's* own file scope so that imported
        parents (``from .base import Base``; ``import animals``) bind correctly,
        with a final fall-back to the global longest-suffix class index.
        """
        if scope is not None:
            hit = scope.classes.get(name)            # local def or imported parent
            if hit is not None:
                return hit
            if "." in name:                          # ``alias.Base`` / ``pkg.Base``
                head, _, tail = name.partition(".")
                dotted = scope.module_aliases.get(head)
                if dotted is not None:
                    ci = self.resolve_class_dotted(f"{dotted}.{tail}")
                    if ci is not None:
                        return ci
        return self.resolve_class_dotted(name)

    def iter_bases(self, info: ClassInfo) -> Iterator[ClassInfo]:
        """Yield the *direct* first-party base classes of *info* (external or
        unresolvable parents are silently skipped)."""
        scope = self.scopes.get(info.file_path)
        for raw in info.base_classes:
            base = self._resolve_base_name(scope, raw)
            if base is not None:
                yield base

    def mro_classes(self, info: ClassInfo) -> List[ClassInfo]:
        """A linearised, cycle-safe method-resolution order starting at *info*.

        A breadth-first walk over ``base_classes`` — close enough to CPython's C3
        for static dispatch and robust against the malformed / cyclic hierarchies
        that turn up in real third-party code.
        """
        order: List[ClassInfo] = []
        seen: Set[str] = set()
        queue: List[ClassInfo] = [info]
        while queue:
            cur = queue.pop(0)
            if cur.qualified in seen:
                continue
            seen.add(cur.qualified)
            order.append(cur)
            queue.extend(self.iter_bases(cur))
        return order

    def resolve_method_mro(self, info: ClassInfo,
                           method: str) -> Optional[FunctionNode]:
        """First definition of *method* found walking *info*'s MRO (own then
        inherited), or ``None`` if no ancestor defines it."""
        for cls in self.mro_classes(info):
            node = cls.methods.get(method)
            if node is not None:
                return node
        return None

    # -- pass 2: per-file scope -----------------------------------

    def _build_scope(self, path: Path, tree: ast.Module) -> ModuleScope:
        mod = self.module_dotted(path)
        scope = ModuleScope(file_path=path, module_dotted=mod)

        # Local definitions first (they shadow imports of the same name).
        for info in self.classes:
            if info.file_path == path:
                scope.classes[info.name] = info
                scope.local_classes[info.name] = info
        for fn in self.functions:
            # module-level funcs have qualified == mod + "." + name and a bare
            # function_name (methods carry "Class.method", so "." in the name
            # filters them out here).
            if str(Path(fn.file_path)) == str(path) and "." not in fn.function_name:
                scope.local_funcs[fn.function_name] = fn

        # Resolve imports into the scope.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._scope_import(scope, node)
            elif isinstance(node, ast.ImportFrom):
                self._scope_import_from(scope, node)
        return scope

    def _scope_import(self, scope: ModuleScope, node: ast.Import) -> None:
        for alias in node.names:
            full = alias.name                        # dotted module being imported
            if alias.asname:                         # import a.b.c as m
                bind, target = alias.asname, full
            else:                                    # import a / import a.b.c
                bind = target = full.split(".")[0]
            # Internal modules feed the in-library resolver; external ones become
            # boundary aliases instead of being dropped.
            sink = (scope.module_aliases if self.is_internal_module(full)
                    else scope.external_modules)
            sink.setdefault(bind, target)
            sink.setdefault(full, full)

    def _scope_import_from(self, scope: ModuleScope, node: ast.ImportFrom) -> None:
        # Relative levels are ignored when matching, but a relative import
        # (``from .mod import X``) is by definition internal to the package.
        base = node.module or ""
        internal = bool(node.level) or self.is_internal_module(base)
        for alias in node.names:
            if alias.name == "*":
                continue
            bind = alias.asname or alias.name
            dotted = self._join(base, alias.name)
            if internal:
                # Try class, then function; record whichever resolves.
                ci = self.resolve_class_dotted(dotted)
                if ci is not None:
                    scope.classes.setdefault(bind, ci)
                else:
                    fn = self.resolve_func_dotted(dotted)
                    if fn is not None:
                        scope.imported_funcs.setdefault(bind, fn)
                # The imported name might also be a submodule used as ``bind.attr()``.
                scope.module_aliases.setdefault(bind, dotted)
            else:
                # Cross-TPL: ``from werkzeug import serving`` records both a bare
                # callable (``serving()``) and a submodule (``serving.run_simple()``).
                scope.external_funcs.setdefault(bind, (base, alias.name))
                scope.external_modules.setdefault(bind, dotted)


# ══════════════════════════════════════════════════════════════════
# LAYER 1 — AST CANDIDATE GENERATOR  (broad net / high recall)
# ══════════════════════════════════════════════════════════════════

class ASTCandidateGenerator(ast.NodeVisitor):
    """Pure-syntactic generation of *tentative* call edges for one function.

    Walks the body of a single definition (never descending into nested
    ``def`` / ``class`` scopes — those are analysed on their own) and, for each
    call expression, emits one or more :class:`Candidate` edges:

      * ``f()``        → the local / imported function ``f`` (exact, not prunable).
      * ``Cls()``      → ``Cls.__init__`` constructor edge (exact, not prunable).
      * ``mod.f()``    → function ``f`` inside module alias ``mod`` (exact).
      * ``super().m()`` → method ``m`` resolved through the *enclosing* class's
                         parents via the MRO (inheritance-aware, not prunable).
      * ``x.m()``      → **every** in-scope class whose MRO resolves a method ``m``
                         (own *or* inherited — the broad net, prunable,
                         base_var=``x``).

    Candidates are keyed by ``id(call_node)`` so Layer 2 can re-discover the very
    same call sites during its flow-sensitive pass and prune them.
    """

    def __init__(self, index: LibraryIndex, scope: ModuleScope,
                 enclosing: Optional[ClassInfo] = None) -> None:
        self.index = index
        self.scope = scope
        self.enclosing = enclosing          # class owning this def (for super())
        self.sites: Dict[int, List[Candidate]] = {}

    def generate(self, func_def: _FuncDef) -> Dict[int, List[Candidate]]:
        for stmt in func_def.body:
            self.visit(stmt)
        return self.sites

    # Scope barriers: nested definitions are separate units of analysis.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:            # noqa: N802
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:                  # noqa: N802
        return None

    def visit_Call(self, node: ast.Call) -> None:                          # noqa: N802
        try:
            cands = self._candidates(node)
        except Exception as exc:        # one odd call must not abort generation
            logger.debug("[LibGraph] candidate-gen error in %s: %s",
                         self.scope.file_path, exc)
            cands = []
        if cands:
            self.sites[id(node)] = cands
        self.generic_visit(node)        # recurse into nested calls in the args

    # -- candidate construction -----------------------------------

    def _candidates(self, node: ast.Call) -> List[Candidate]:
        func = node.func
        if isinstance(func, ast.Name):
            return self._candidates_name(func.id, node)
        if isinstance(func, ast.Attribute):
            # ``super().m()`` / ``super(Child, self).m()`` — the receiver is a
            # ``super()`` proxy, not a plain Name, so it needs the MRO walk.
            if self._is_super_call(func.value):
                return self._candidates_super(func.attr, node)
            if isinstance(func.value, ast.Name):
                return self._candidates_attr(func.value.id, func.attr, node)
        return []                        # deep chains / subscripts -> LLM territory

    @staticmethod
    def _is_super_call(expr: ast.expr) -> bool:
        return (isinstance(expr, ast.Call)
                and isinstance(expr.func, ast.Name)
                and expr.func.id == "super")

    def _candidates_super(self, method: str, node: ast.Call) -> List[Candidate]:
        """``super().m()`` → method ``m`` in the enclosing class's ancestors.

        Statically we cannot know the runtime MRO (a subclass instance could
        re-route ``super`` through a sibling), so we tentatively bind to the first
        ``m`` reachable from *each* direct parent. There is no receiver variable to
        key points-to on, so these edges are non-prunable — Layer 2 ignores them.
        """
        if self.enclosing is None:
            return []
        out: List[Candidate] = []
        seen: Set[str] = set()
        for base in self.index.iter_bases(self.enclosing):
            meth = self.index.resolve_method_mro(base, method)
            if meth is not None and meth.qualified_name not in seen:
                seen.add(meth.qualified_name)
                out.append(Candidate(meth, owner=None, base_var=None,
                                     call_node=node, prunable=False))
        return out

    def _candidates_name(self, name: str, node: ast.Call) -> List[Candidate]:
        # Constructor call ``Cls()``.
        ci = self.scope.classes.get(name)
        if ci is not None:
            init = ci.methods.get("__init__")
            if init is not None:
                return [Candidate(init, owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            return []
        # Plain function ``f()`` — local def or ``from mod import f``.
        fn = self.scope.local_funcs.get(name) or self.scope.imported_funcs.get(name)
        if fn is not None:
            return [Candidate(fn, owner=None, base_var=None,
                              call_node=node, prunable=False)]
        # External function ``f()`` pulled in via ``from <tpl> import f`` — an
        # exact cross-TPL boundary edge, not something to drop.
        ext = self.scope.external_funcs.get(name)
        if ext is not None:
            module, symbol = ext
            return [Candidate(_make_external_node(module, symbol, node.lineno),
                              owner=None, base_var=None,
                              call_node=node, prunable=False)]
        return []

    def _candidates_attr(self, base: str, method: str,
                         node: ast.Call) -> List[Candidate]:
        # 1. Module-qualified call ``mod.func()`` / ``mod.Class()``.
        dotted = self.scope.module_aliases.get(base)
        if dotted is not None:
            target = self._join(dotted, method)
            fn = self.index.resolve_func_dotted(target)
            if fn is not None:
                return [Candidate(fn, owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            ci = self.index.resolve_class_dotted(target)
            if ci is not None and "__init__" in ci.methods:
                return [Candidate(ci.methods["__init__"], owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            # `base` is a module alias but didn't resolve a member — do NOT also
            # treat it as an object receiver (that would invent bogus edges).
            return []

        # 2. External module-qualified call ``tpl.func()`` — exact boundary edge
        #    to an ExternalNode. Static target is the imported symbol, so this is
        #    non-prunable and Layer 2 leaves it untouched.
        ext = self.scope.external_modules.get(base)
        if ext is not None:
            return [Candidate(_make_external_node(ext, method, node.lineno),
                              owner=None, base_var=None,
                              call_node=node, prunable=False)]

        # 3. Object method dispatch ``x.m()`` — the BROAD NET. Every in-scope
        #    class whose MRO resolves a method `m` (defined on the class itself OR
        #    inherited from a parent) is a tentative target. Crucially, ``owner``
        #    is the *receiver* class while ``callee`` is the method's actual
        #    defining node: so when Layer 2 proves ``pt(x) = {Child}`` and ``Child``
        #    only inherits `m` from ``Base``, the edge ``owner=Child`` survives and
        #    correctly points at ``Base.m`` rather than being wrongly pruned away.
        out: List[Candidate] = []
        seen: Set[str] = set()
        for ci in self.scope.classes.values():
            if ci.qualified in seen:
                continue
            meth = self.index.resolve_method_mro(ci, method)
            if meth is not None:
                seen.add(ci.qualified)
                out.append(Candidate(meth, owner=ci.qualified, base_var=base,
                                     call_node=node, prunable=True))
        return out

    @staticmethod
    def _join(*parts: str) -> str:
        return ".".join(p for p in parts if p)


# ══════════════════════════════════════════════════════════════════
# LAYER 2 — ANDERSEN POINTS-TO ANALYZER  (fine filter / flow-sensitive)
# ══════════════════════════════════════════════════════════════════

class AndersenPointsToAnalyzer:
    """Flow-sensitive points-to analysis that records the receiver type at each
    call site — the precision "brain" that prunes Layer 1's over-approximation.

    The analyzer threads a :class:`PointsToState` (``var -> {qualified class}``)
    through the statements of a function **in source order**. Key semantics:

      * **Strong update** on an *unconditional* assignment: ``x = Dog()`` sets
        ``pt(x) = {Dog}``, completely *overwriting* the previous value of ``pt(x)``
        (this is what makes the analysis flow-sensitive rather than a flat union).
      * **Weak update** inside a conditional branch (``if`` / loop / ``try``):
        the new type is *merged* with the existing one, because the assignment
        may or may not have executed on the path reaching a later use.
      * **Top (unknown)** is represented by the *absence* of a key. An assignment
        whose right-hand side we cannot type (a non-constructor call, a parameter,
        an attribute read) drives the variable to top, so we never prune on a
        guess.
      * **Branch join**: after an ``if`` / loop / ``try`` the per-path states are
        joined — a variable keeps a concrete type only if it is the same/known on
        every path, otherwise it falls to top (sound over-approximation).

    For a method, ``self`` / ``cls`` are seeded to the enclosing class, which both
    types ``self.m()`` precisely and lets ``x = self`` propagate.

    The result, :attr:`call_pt`, maps ``id(call_node) -> Optional[PointsToSet]``:
    a concrete set when the receiver's type is known at that point, or ``None``
    (top) when it is not — the orchestrator keeps all candidates in the top case.
    """

    def __init__(self, index: LibraryIndex, scope: ModuleScope,
                 enclosing: Optional[ClassInfo]) -> None:
        self.index = index
        self.scope = scope
        self.enclosing = enclosing
        self.call_pt: Dict[int, Optional[PointsToSet]] = {}

    def compute(self, func_def: _FuncDef) -> Dict[int, Optional[PointsToSet]]:
        state: PointsToState = {}
        if self.enclosing is not None:
            state["self"] = {self.enclosing.qualified}
            state["cls"] = {self.enclosing.qualified}
        try:
            self._walk_stmts(func_def.body, state, conditional=False)
        except Exception as exc:        # never let analysis abort the build
            logger.debug("[LibGraph] points-to error in %s: %s",
                         self.scope.file_path, exc)
        return self.call_pt

    # -- statement walker -----------------------------------------

    def _walk_stmts(self, stmts: List[ast.stmt], state: PointsToState,
                    conditional: bool) -> PointsToState:
        for stmt in stmts:
            state = self._walk_stmt(stmt, state, conditional)
        return state

    def _walk_stmt(self, stmt: ast.stmt, state: PointsToState,
                   conditional: bool) -> PointsToState:
        # Scope barriers — never descend into nested definitions.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return state

        if isinstance(stmt, ast.Assign):
            return self._walk_assign(stmt, state, conditional)
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._walk_expr(stmt.value, state)
                if isinstance(stmt.target, ast.Name):
                    self._update(state, stmt.target.id,
                                 self._eval_types(stmt.value, state), conditional)
            return state
        if isinstance(stmt, ast.AugAssign):
            self._walk_expr(stmt.value, state)
            self._assign_top(stmt.target, state)     # x += ... -> conservatively top
            return state
        if isinstance(stmt, ast.If):
            self._walk_expr(stmt.test, state)
            st = self._walk_stmts(stmt.body, self._copy(state), True)
            sf = self._walk_stmts(stmt.orelse, self._copy(state), True)
            return self._join(st, sf)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._walk_expr(stmt.iter, state)
            self._assign_top(stmt.target, state)     # loop variable: unknown type
            body = self._walk_stmts(stmt.body, self._copy(state), True)
            orelse = self._walk_stmts(stmt.orelse, self._copy(state), True)
            # Loop may run zero times -> also fold in the pre-loop state.
            return self._join(self._join(body, orelse), state)
        if isinstance(stmt, ast.While):
            self._walk_expr(stmt.test, state)
            body = self._walk_stmts(stmt.body, self._copy(state), True)
            orelse = self._walk_stmts(stmt.orelse, self._copy(state), True)
            return self._join(self._join(body, orelse), state)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self._walk_with(stmt, state, conditional)
        if isinstance(stmt, ast.Try):
            return self._walk_try(stmt, state, conditional)

        # Default: record any calls in the statement's expressions, recurse into
        # nested statement lists conditionally. Tracked state is left unchanged.
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._walk_expr(child, state)
            elif isinstance(child, ast.stmt):
                state = self._walk_stmt(child, state, conditional)
        return state

    def _walk_assign(self, node: ast.Assign, state: PointsToState,
                     conditional: bool) -> PointsToState:
        # RHS is evaluated (and its calls recorded) under the *pre*-assignment
        # state, which is correct for ``x = x.m()``.
        self._walk_expr(node.value, state)
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            types = self._eval_types(node.value, state)
            self._update(state, node.targets[0].id, types, conditional)
        else:
            for target in node.targets:              # tuple/attr/multiple -> top
                self._assign_top(target, state)
        return state

    def _walk_with(self, stmt: Union[ast.With, ast.AsyncWith],
                   state: PointsToState, conditional: bool) -> PointsToState:
        for item in stmt.items:
            self._walk_expr(item.context_expr, state)
            if isinstance(item.optional_vars, ast.Name):
                self._update(state, item.optional_vars.id,
                             self._eval_types(item.context_expr, state), conditional)
            elif item.optional_vars is not None:
                self._assign_top(item.optional_vars, state)
        # The with-body executes in the current (un)conditional context.
        return self._walk_stmts(stmt.body, state, conditional)

    def _walk_try(self, stmt: ast.Try, state: PointsToState,
                  conditional: bool) -> PointsToState:
        states = [self._walk_stmts(stmt.body, self._copy(state), True)]
        for handler in stmt.handlers:
            states.append(self._walk_stmts(handler.body, self._copy(state), True))
        if stmt.orelse:
            states.append(self._walk_stmts(stmt.orelse, self._copy(states[0]), True))
        joined = states[0]
        for other in states[1:]:
            joined = self._join(joined, other)
        # ``finally`` always runs -> apply it in the incoming (un)conditional ctx.
        return self._walk_stmts(stmt.finalbody, joined, conditional)

    # -- expression walker (records receiver points-to at call sites) --

    def _walk_expr(self, expr: ast.AST, state: PointsToState) -> None:
        if isinstance(expr, ast.Call):
            func = expr.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                base = func.value.id
                current = state.get(base)
                # Concrete set if known, else None (= top: receiver type unknown).
                self.call_pt[id(expr)] = set(current) if current is not None else None
        for child in ast.iter_child_nodes(expr):
            self._walk_expr(child, state)

    # -- type evaluation of a right-hand side ---------------------

    def _eval_types(self, value: ast.expr, state: PointsToState) -> Optional[PointsToSet]:
        """The set of classes an assigned RHS may produce, or ``None`` for top."""
        if isinstance(value, ast.Call):
            ci = self._resolve_class_expr(value.func)
            if ci is not None:                       # constructor -> instance type
                return {ci.qualified}
            return None                              # function return type unknown
        if isinstance(value, ast.Name):              # x = y -> copy pt(y)
            current = state.get(value.id)
            return set(current) if current is not None else None
        return None                                  # literals/attrs/etc. -> top

    def _resolve_class_expr(self, func: ast.expr) -> Optional[ClassInfo]:
        """Resolve a constructor expression (``Cls`` or ``mod.Cls``) to a class."""
        if isinstance(func, ast.Name):
            return self.scope.classes.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            dotted = self.scope.module_aliases.get(func.value.id)
            if dotted is not None:
                return self.index.resolve_class_dotted(f"{dotted}.{func.attr}")
        return None

    # -- state algebra --------------------------------------------

    @staticmethod
    def _copy(state: PointsToState) -> PointsToState:
        return {name: set(types) for name, types in state.items()}

    @staticmethod
    def _join(a: PointsToState, b: PointsToState) -> PointsToState:
        """Sound join: a variable survives with a concrete type only if both
        paths give it a *known* type (then union); otherwise it falls to top."""
        joined: PointsToState = {}
        for name in a.keys() & b.keys():
            joined[name] = a[name] | b[name]
        return joined

    def _update(self, state: PointsToState, name: str,
                types: Optional[PointsToSet], conditional: bool) -> None:
        if types is None:                            # RHS unknown -> drive to top
            state.pop(name, None)
            return
        if conditional:                              # weak update: merge with prior
            if name in state:
                state[name] = state[name] | types
            else:
                # Previously top (or undefined on the other path) ∪ known = top.
                state.pop(name, None)
        else:                                        # strong update: overwrite
            state[name] = set(types)

    def _assign_top(self, target: ast.expr, state: PointsToState) -> None:
        """Drive every Name bound by *target* to top (unknown)."""
        if isinstance(target, ast.Name):
            state.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_top(elt, state)
        # Attribute / Subscript targets bind no tracked local -> nothing to do.


# ══════════════════════════════════════════════════════════════════
# ORCHESTRATOR — drives Layer 1 + Layer 2 over the whole library
# ══════════════════════════════════════════════════════════════════

class LibraryAnalyzer:
    """Coordinate exhaustive indexing, candidate generation and points-to pruning
    into a single library call graph (G_L)."""

    def __init__(self) -> None:
        self.index: Optional[LibraryIndex] = None
        self._seen_edges: Set[Tuple[FunctionNode, FunctionNode]] = set()

    # -- public API -----------------------------------------------

    def build_library_graph(self, library_root: Path) -> CallGraph:
        """Build the exhaustive library call graph rooted at *library_root*.

        Every function and method defined under the root becomes a node; every
        statically-resolvable (and points-to-confirmed) call becomes an edge.
        Unreadable / unparsable modules are skipped, never fatal.
        """
        root = Path(library_root)
        if not root.exists():
            raise FileNotFoundError(f"Library root does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Library root is not a directory: {root}")

        self.index = LibraryIndex(root).build()
        graph = CallGraph()

        # Seed the graph with the full API surface + internal functions so even
        # never-called definitions are represented as nodes.
        for fn in self.index.functions:
            graph.add_node(fn)

        for path, scope in self.index.scopes.items():
            tree = self.index.asts.get(path)
            if tree is None:
                continue
            for func_def, caller, enclosing in self._iter_defs(tree, scope):
                try:
                    callees = self._analyze_definition(func_def, scope, enclosing)
                except Exception as exc:    # one bad definition never kills build
                    logger.warning("[LibGraph] Failed to analyze %s in %s: %s",
                                   caller.function_name, path, exc)
                    continue
                for callee in callees:
                    graph.add_node(callee)
                    key = (caller, callee)
                    if key not in self._seen_edges:
                        self._seen_edges.add(key)
                        graph.edges.append(CallEdge(caller=caller, callee=callee))

        logger.info("[LibGraph] Built G_L: %d node(s), %d edge(s)",
                    len(graph.nodes), len(graph.edges))
        return graph

    # -- definition iteration -------------------------------------

    def _iter_defs(self, tree: ast.Module, scope: ModuleScope
                   ) -> Iterator[Tuple[_FuncDef, FunctionNode, Optional[ClassInfo]]]:
        """Yield ``(def_node, canonical_caller_node, enclosing_class)`` for every
        top-level function and direct method in *tree*. The caller node is fetched
        from the index so its identity matches the callee nodes produced elsewhere.
        """
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = scope.local_funcs.get(node.name)
                if fn is not None:
                    yield node, fn, None
            elif isinstance(node, ast.ClassDef):
                ci = scope.local_classes.get(node.name)
                if ci is None:
                    continue
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        mnode = ci.methods.get(sub.name)
                        if mnode is not None:
                            yield sub, mnode, ci

    # -- per-definition analysis (Layer 1 -> Layer 2) -------------

    def _analyze_definition(self, func_def: _FuncDef, scope: ModuleScope,
                            enclosing: Optional[ClassInfo]) -> List[FunctionNode]:
        assert self.index is not None
        # Layer 1: broad tentative edges keyed by call site (enclosing class is
        # passed so ``super().m()`` can be resolved through the MRO).
        sites = ASTCandidateGenerator(self.index, scope, enclosing).generate(func_def)
        if not sites:
            return []
        # Layer 2: flow-sensitive receiver types at each call site.
        pt = AndersenPointsToAnalyzer(self.index, scope, enclosing).compute(func_def)

        callees: List[FunctionNode] = []
        for site_id, cands in sites.items():
            callees.extend(self._refine(cands, pt.get(site_id)))
        return callees

    def _refine(self, cands: List[Candidate],
                receiver_pt: Optional[PointsToSet]) -> List[FunctionNode]:
        """Apply Layer-2 judgement to one call site's Layer-1 candidates."""
        keep: List[FunctionNode] = [c.callee for c in cands if not c.prunable]
        prunable = [c for c in cands if c.prunable]
        if not prunable:
            return keep

        call_node = prunable[0].call_node

        if receiver_pt is None:
            # Receiver type unknown (top). Static pruning is unsafe — defer to the
            # LLM oracle; if it abstains, keep the full broad net (preserve recall).
            resolved = self._resolve_with_llm(call_node)
            if resolved is not None:
                keep.append(resolved)
            else:
                keep.extend(c.callee for c in prunable)
            return keep

        # Receiver type is concrete -> keep only candidates whose owning class is
        # in the points-to set; this is where the spurious edges get dropped.
        matched = [c.callee for c in prunable if c.owner in receiver_pt]
        if matched:
            keep.extend(matched)
        else:
            # Type known but matches no candidate (e.g. a stdlib/3rd-party object):
            # nothing to keep statically — give the oracle one last chance.
            resolved = self._resolve_with_llm(call_node)
            if resolved is not None:
                keep.append(resolved)
        return keep

    # -- LLM ORACLE (stub) ----------------------------------------

    def _resolve_with_llm(self, call_node: ast.Call) -> Optional[FunctionNode]:
        """Placeholder for the future LLM disambiguation oracle.

        When both static layers fail to pin down a call's target — typically
        genuinely dynamic dispatch such as ``getattr(obj, name)()``, factory
        return values, or reflective ``__getattr__`` patterns — this hook will
        prompt an LLM with the call's source context and resolve it to a concrete
        :class:`FunctionNode`.

        For this iteration it is a deliberate no-op (always ``None``) so the
        pipeline degrades to "keep the broad net" rather than guessing. The real
        prompt construction and response parsing land in a later phase.
        """
        return None


# ══════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def build_library_graph(library_root: Path) -> CallGraph:
    """Exhaustively build the library call graph (G_L) under *library_root*.

    Convenience wrapper around :class:`LibraryAnalyzer` — the canonical entry
    point referenced by the rest of the PyShare pipeline.

    Parameters
    ----------
    library_root:
        Root directory of the third-party library to analyse.

    Returns
    -------
    CallGraph
        ``nodes`` = every function / method defined in the library; ``edges`` =
        the directed, points-to-refined call relationships between them.
    """
    return LibraryAnalyzer().build_library_graph(Path(library_root))
