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
    :class:`~pyshare_core.models.CallGraph`. The shared construction pipeline
    also hosts the future :meth:`CallGraphConstructionPipeline.resolve_dynamic_call`
    oracle hook (a no-op stub for now)
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
import symtable as py_symtable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple, Union

from pyshare_core.models import (
    CallEdge,
    CallGraph,
    CandidateEdge,
    EntryPointType,
    ExternalNode,
    FunctionNode,
    UnresolvedCall,
)

logger = logging.getLogger(__name__)

PathLike = Union[str, "os.PathLike[str]"]
CANDIDATE_FANOUT_CAP = 20

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

def _safe_parse(path: Path, skipped_files: Optional[List[dict]] = None) -> Optional[ast.Module]:
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
        if skipped_files is not None:
            skipped_files.append({"file_path": str(path), "reason": "read_error", "detail": str(exc)})
        return None

    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        logger.warning("[LibGraph] Skipping %s (syntax error: %s)", path, exc)
        if skipped_files is not None:
            skipped_files.append(
                {
                    "file_path": str(path),
                    "reason": "syntax_error",
                    "line_number": getattr(exc, "lineno", 0) or 0,
                    "detail": str(exc),
                }
            )
        return None
    except (ValueError, RecursionError) as exc:
        # ValueError: null bytes in source; RecursionError: pathological nesting.
        logger.warning("[LibGraph] Skipping %s (parse failure: %s)", path, exc)
        if skipped_files is not None:
            skipped_files.append({"file_path": str(path), "reason": "parse_failure", "detail": str(exc)})
        return None


def _safe_symtable(path: Path) -> Optional[py_symtable.SymbolTable]:
    """Build Python's lexical symbol table for *path*, returning ``None`` safely."""
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("[LibGraph] Cannot read symbols from %s: %s", path, exc)
        return None

    try:
        return py_symtable.symtable(source, str(path), "exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        logger.warning("[LibGraph] Skipping symbols for %s: %s", path, exc)
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
    edge_type: str = "confirmed_static"
    confidence: float = 1.0
    resolver: str = "static"
    reason: str = ""


@dataclass
class FunctionSummary:
    param_types: Dict[str, PointsToSet] = field(default_factory=dict)
    return_types: PointsToSet = field(default_factory=set)
    call_edges: List[dict] = field(default_factory=list)
    external_edges: List[dict] = field(default_factory=list)
    unresolved_calls: List[dict] = field(default_factory=list)
    evidence: List[dict] = field(default_factory=list)


EXTERNAL_CALL_RETURN_TYPES: Dict[str, PointsToSet] = {
    "sqlite3.connect": {"external:sqlite3.Connection"},
}

EXTERNAL_METHOD_RETURN_TYPES: Dict[Tuple[str, str], Optional[PointsToSet]] = {
    ("sqlite3.Connection", "execute"): {"external:sqlite3.Cursor"},
    ("sqlite3.Cursor", "fetchall"): {"external:builtins.list"},
    ("sqlite3.Connection", "close"): set(),
}


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


def _type_external(dotted: str) -> str:
    return f"external:{dotted}"


def _type_factory(call_name: str) -> str:
    return f"factory:{call_name or '?'}"


def _is_external_type(value: str) -> bool:
    return value.startswith("external:")


def _external_type_name(value: str) -> str:
    return value.split(":", 1)[1]


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
        self.virtual_sources: Dict[Path, str] = {}
        self.symbol_tables: Dict[Path, py_symtable.SymbolTable] = {}
        self.classes: List[ClassInfo] = []
        self.functions: List[FunctionNode] = []
        self.public_api: List[FunctionNode] = []
        self.scopes: Dict[Path, ModuleScope] = {}
        self.class_defs: Dict[str, ast.ClassDef] = {}
        self.class_attribute_types: Dict[str, Dict[str, PointsToSet]] = {}
        self.function_defs: Dict[str, _FuncDef] = {}
        self.function_params: Dict[str, List[str]] = {}
        self.skipped_files: List[dict] = []
        self.unresolved_public_exports: List[dict] = []
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
            tree = _safe_parse(path, self.skipped_files)
            if tree is None:
                continue
            self.asts[path] = tree
            symbols = _safe_symtable(path)
            if symbols is not None:
                self.symbol_tables[path] = symbols
            self._register_module_suffixes(self.module_dotted(path))
            self._collect_definitions(path, tree)
            self._collect_embedded_python_sources(path, tree)
        # Pass 2: now that all symbols exist, resolve each file's imports.
        for path, tree in self.asts.items():
            self.scopes[path] = self._build_scope(path, tree)
        self._collect_class_attribute_types()
        logger.info("[LibGraph] Indexed %d class(es), %d function(s) across %d file(s)",
                    len(self.classes), len(self.functions), len(self.asts))
        return self

    def _collect_embedded_python_sources(self, host_path: Path, tree: ast.Module) -> None:
        """Index string-literal Python files embedded in generator scripts.

        Some real benchmark clients ship as a script that writes a small project
        from a ``{"path.py": "...source..."}`` mapping. We keep this static by
        parsing only literal strings whose keys look like Python file paths.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if not (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value.endswith(".py")
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    continue
                source = value.value
                try:
                    embedded_tree = ast.parse(source, filename=key.value)
                except SyntaxError:
                    continue
                virtual_path = host_path.parent / "__embedded_sources__" / key.value
                if virtual_path in self.asts:
                    continue
                self.virtual_sources[virtual_path] = source
                self.asts[virtual_path] = embedded_tree
                self._register_module_suffixes(self.module_dotted(virtual_path))
                self._collect_definitions(virtual_path, embedded_tree)

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
                                          self._join(mod, node.name), node.lineno,
                                          module=mod, scope="", def_node=node)
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
        self.class_defs[qualified] = cls
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
                    module=mod,
                    scope=cls.name,
                    def_node=sub,
                )
                info.methods.setdefault(sub.name, node)
                self.functions.append(node)
                if not sub.name.startswith("_") or sub.name == "__init__":
                    self.public_api.append(node)
        self.classes.append(info)
        self._index_class(info)

    def _collect_class_attribute_types(self) -> None:
        """Summarize constructor-written attributes for reuse by other methods.

        This is a lightweight function-level type graph reuse step: facts like
        ``self.client = Client()`` in ``__init__`` are seeded into later method
        analyses so ``self.client.request()`` can be resolved without executing
        or inlining the constructor.
        """
        for info in self.classes:
            cls = self.class_defs.get(info.qualified)
            scope = self.scopes.get(info.file_path)
            if cls is None or scope is None:
                continue
            init = next(
                (
                    node
                    for node in cls.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "__init__"
                ),
                None,
            )
            if init is None:
                continue
            attrs: Dict[str, PointsToSet] = {}
            for stmt in ast.walk(init):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stmt is not init:
                    continue
                if isinstance(stmt, ast.Assign):
                    types = self._constructor_types(stmt.value, scope)
                    if not types:
                        continue
                    for target in stmt.targets:
                        name = self._self_attribute_name(target)
                        if name is not None:
                            attrs[name] = set(types)
                elif isinstance(stmt, ast.AnnAssign):
                    types = self._constructor_types(stmt.value, scope) if stmt.value is not None else None
                    name = self._self_attribute_name(stmt.target)
                    if name is not None and types:
                        attrs[name] = set(types)
            if attrs:
                self.class_attribute_types[info.qualified] = attrs

    @staticmethod
    def _self_attribute_name(target: ast.AST) -> Optional[str]:
        if not isinstance(target, ast.Attribute):
            return None
        try:
            base = ast.unparse(target.value)
        except Exception:
            return None
        if base != "self":
            return None
        return f"self.{target.attr}"

    def _constructor_types(self, value: Optional[ast.expr], scope: ModuleScope) -> Optional[PointsToSet]:
        if not isinstance(value, ast.Call):
            return None
        ci: Optional[ClassInfo] = None
        if isinstance(value.func, ast.Name):
            ci = scope.classes.get(value.func.id)
        elif isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            dotted = scope.module_aliases.get(value.func.value.id)
            if dotted is not None:
                ci = self.resolve_class_dotted(f"{dotted}.{value.func.attr}")
        return {ci.qualified} if ci is not None else None

    def _make_func_node(
        self,
        path: Path,
        function_name: str,
        method_name: str,
        qualified: str,
        line: int,
        *,
        module: str,
        scope: str,
        def_node: _FuncDef,
    ) -> FunctionNode:
        node = FunctionNode(
            file_path=str(path),
            function_name=function_name,
            qualified_name=qualified,
            line_number=line,
            module=module,
            scope=scope,
            signature=self._signature(def_node.args),
            arity=self._callable_arity(def_node.args, method_name, bool(scope)),
            source_snippet=self._source_snippet(path, def_node, self.virtual_sources.get(path)),
            entry_type=EntryPointType.UNKNOWN,
        )
        self.function_defs[qualified] = def_node
        self.function_defs[function_name] = def_node
        self.function_params[qualified] = self._callable_params(def_node.args, method_name, bool(scope))
        return node

    @staticmethod
    def _signature(args: ast.arguments) -> str:
        try:
            return f"({ast.unparse(args)})"
        except Exception:
            return "()"

    @staticmethod
    def _callable_arity(args: ast.arguments, method_name: str, is_method: bool) -> int:
        count = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
        if is_method and method_name != "__new__" and count > 0:
            first = (args.posonlyargs + args.args)[0].arg if (args.posonlyargs + args.args) else ""
            if first in {"self", "cls"}:
                count -= 1
        return max(count, 0)

    @staticmethod
    def _callable_params(args: ast.arguments, method_name: str, is_method: bool) -> List[str]:
        params = [arg.arg for arg in (args.posonlyargs + args.args)]
        if is_method and method_name != "__new__" and params and params[0] in {"self", "cls"}:
            params = params[1:]
        params.extend(arg.arg for arg in args.kwonlyargs)
        return params

    @staticmethod
    def _source_snippet(path: Path, node: _FuncDef, source: str | None = None) -> str:
        if source is not None:
            lines = source.splitlines()
        else:
            try:
                lines = path.read_text(encoding="utf-8-sig").splitlines()
            except (OSError, UnicodeDecodeError):
                return ""
        start = max(getattr(node, "lineno", 1) - 1, 0)
        end = getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)
        return "\n".join(lines[start:end])[:4000]

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

    # -- public API aliases --------------------------------------

    def public_api_aliases(self) -> Dict[str, str]:
        """Return public root-package re-exports as alias -> canonical target.

        Package users often call a symbol exposed from ``__init__.py`` while the
        implementation lives deeper in the tree, e.g. ``pkg.public`` re-exporting
        ``pkg.impl.public``. Reports store aliases relative to the package root,
        including subpackage prefixes when present, so callers can choose the
        import root later with ``--package-report ROOT=PATH``.
        """
        aliases: Dict[str, str] = {}
        for scope in self.scopes.values():
            if scope.file_path.name != "__init__.py":
                continue
            for name, fn in scope.imported_funcs.items():
                if name.startswith("_"):
                    continue
                alias = self._join(scope.module_dotted, name)
                target = fn.qualified_name or fn.function_name
                if target and target != alias:
                    aliases.setdefault(alias, target)
            for name, info in scope.classes.items():
                if name.startswith("_"):
                    continue
                alias = self._join(scope.module_dotted, name)
                init = info.methods.get("__init__")
                target = init.qualified_name if init is not None else info.qualified
                if target and target != alias:
                    aliases.setdefault(alias, target)
        return dict(sorted(aliases.items()))

    def public_export_warnings(self) -> List[dict]:
        return list(self.unresolved_public_exports)

    def _module_path(self, dotted: str) -> Optional[Path]:
        for path in self.asts:
            if self.module_dotted(path) == dotted:
                return path
        return None

    def _module_all(self, dotted: str) -> Optional[List[str]]:
        path = self._module_path(dotted)
        tree = self.asts.get(path) if path is not None else None
        if tree is None:
            return None
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                continue
            value = node.value
            names = self._literal_str_sequence(value) if value is not None else None
            if names is None:
                self.unresolved_public_exports.append(
                    {
                        "module": dotted,
                        "file_path": str(path),
                        "reason": "dynamic __all__ is not statically resolvable",
                    }
                )
            return names
        return None

    @staticmethod
    def _literal_str_sequence(node: ast.AST) -> Optional[List[str]]:
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return None
        out: List[str] = []
        for elt in node.elts:
            if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
                return None
            out.append(elt.value)
        return out

    def _module_export_names(self, dotted: str) -> List[str]:
        explicit = self._module_all(dotted)
        if explicit is not None:
            return [name for name in explicit if name and not name.startswith("_")]

        names: Set[str] = set()
        for fn in self.functions:
            if fn.module == dotted and "." not in fn.function_name and not fn.function_name.startswith("_"):
                names.add(fn.function_name)
        for cls in self.classes:
            if self.module_dotted(cls.file_path) == dotted and not cls.name.startswith("_"):
                names.add(cls.name)
        return sorted(names)

    def _record_dynamic_exports(self, scope: ModuleScope, tree: ast.Module) -> None:
        if scope.file_path.name != "__init__.py":
            return
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__getattr__":
                self.unresolved_public_exports.append(
                    {
                        "module": scope.module_dotted,
                        "file_path": str(scope.file_path),
                        "line_number": node.lineno,
                        "reason": "module __getattr__ may expose dynamic public symbols",
                    }
                )
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        text = self._call_expr_from_node(target)
                        if text.startswith("globals()[") or text.startswith("locals()["):
                            self.unresolved_public_exports.append(
                                {
                                    "module": scope.module_dotted,
                                    "file_path": str(scope.file_path),
                                    "line_number": node.lineno,
                                    "reason": "dynamic globals()/locals() export assignment",
                                }
                            )

    @staticmethod
    def _call_expr_from_node(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

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
        self._scope_alias_assignments(scope, tree)
        self._record_dynamic_exports(scope, tree)
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
                if internal:
                    for export in self._module_export_names(base):
                        self._scope_import_symbol(scope, base, export)
                else:
                    self.unresolved_public_exports.append(
                        {
                            "module": scope.module_dotted,
                            "file_path": str(scope.file_path),
                            "line_number": node.lineno,
                            "reason": f"external wildcard import from {base or '?'} is not expanded",
                        }
                    )
                continue
            bind = alias.asname or alias.name
            dotted = self._join(base, alias.name)
            if internal:
                self._scope_import_symbol(scope, base, alias.name, bind=bind)
            else:
                # Cross-TPL: ``from werkzeug import serving`` records both a bare
                # callable (``serving()``) and a submodule (``serving.run_simple()``).
                scope.external_funcs.setdefault(bind, (base, alias.name))
                scope.external_modules.setdefault(bind, dotted)

    def _scope_import_symbol(
        self,
        scope: ModuleScope,
        base: str,
        name: str,
        *,
        bind: Optional[str] = None,
    ) -> None:
        bind = bind or name
        dotted = self._join(base, name)
        ci = self.resolve_class_dotted(dotted)
        if ci is not None:
            scope.classes.setdefault(bind, ci)
        else:
            fn = self.resolve_func_dotted(dotted)
            if fn is not None:
                scope.imported_funcs.setdefault(bind, fn)
        scope.module_aliases.setdefault(bind, dotted)

    def _scope_alias_assignments(self, scope: ModuleScope, tree: ast.Module) -> None:
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            target_symbol = self._resolve_alias_value(scope, value)
            if target_symbol is None:
                continue
            kind, resolved = target_symbol
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if kind == "func":
                    scope.imported_funcs.setdefault(target.id, resolved)  # type: ignore[arg-type]
                elif kind == "class":
                    scope.classes.setdefault(target.id, resolved)  # type: ignore[arg-type]

    def _resolve_alias_value(
        self,
        scope: ModuleScope,
        value: ast.expr,
    ) -> Optional[Tuple[str, object]]:
        if isinstance(value, ast.Name):
            if value.id in scope.imported_funcs:
                return ("func", scope.imported_funcs[value.id])
            if value.id in scope.classes:
                return ("class", scope.classes[value.id])
            return None
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            dotted = scope.module_aliases.get(value.value.id)
            if dotted is None:
                return None
            target = self._join(dotted, value.attr)
            fn = self.resolve_func_dotted(target)
            if fn is not None:
                return ("func", fn)
            ci = self.resolve_class_dotted(target)
            if ci is not None:
                return ("class", ci)
        return None


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
        self.unresolved: Dict[int, ast.Call] = {}

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
        else:
            self.unresolved[id(node)] = node
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
            if isinstance(func.value, (ast.Name, ast.Attribute)):
                try:
                    base = ast.unparse(func.value)
                except Exception:
                    base = ""
                return self._candidates_attr(base, func.attr, node)
        return []                        # subscripts / dynamic expressions -> LLM territory

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
        dotted = self._resolve_module_alias(self.scope.module_aliases, base)
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
        ext = self._resolve_module_alias(self.scope.external_modules, base)
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
    def _resolve_module_alias(aliases: Dict[str, str], base: str) -> Optional[str]:
        """Resolve ``alias`` or ``alias.submodule`` using the longest known prefix."""
        if base in aliases:
            return aliases[base]
        parts = [part for part in base.split(".") if part]
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            target = aliases.get(prefix)
            if target is not None:
                suffix = ".".join(parts[i:])
                return ".".join(part for part in (target, suffix) if part)
        return None

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

    def __init__(
        self,
        index: LibraryIndex,
        scope: ModuleScope,
        enclosing: Optional[ClassInfo],
        entry_types: Optional[Dict[str, PointsToSet]] = None,
        function_summaries: Optional[Dict[str, FunctionSummary]] = None,
        in_progress: Optional[Set[str]] = None,
    ) -> None:
        self.index = index
        self.scope = scope
        self.enclosing = enclosing
        self.entry_types = entry_types or {}
        self.function_summaries = function_summaries if function_summaries is not None else {}
        self.in_progress = in_progress if in_progress is not None else set()
        self.call_pt: Dict[int, Optional[PointsToSet]] = {}
        self.call_arg_types: Dict[int, List[Optional[PointsToSet]]] = {}
        self.return_types: PointsToSet = set()
        self.assignment_type_facts: List[dict] = []
        self.return_type_facts: List[dict] = []
        self.external_model_facts: List[dict] = []

    def compute(self, func_def: _FuncDef) -> Dict[int, Optional[PointsToSet]]:
        state: PointsToState = {}
        if self.enclosing is not None:
            state["self"] = {self.enclosing.qualified}
            state["cls"] = {self.enclosing.qualified}
            for attr, types in self.index.class_attribute_types.get(self.enclosing.qualified, {}).items():
                state[attr] = set(types)
        self._seed_parameter_types(func_def, state)
        try:
            self._walk_stmts(func_def.body, state, conditional=False)
        except Exception as exc:        # never let analysis abort the build
            logger.debug("[LibGraph] points-to error in %s: %s",
                         self.scope.file_path, exc)
        return self.call_pt

    def _seed_parameter_types(self, func_def: _FuncDef, state: PointsToState) -> None:
        for arg in func_def.args.posonlyargs + func_def.args.args + func_def.args.kwonlyargs:
            propagated = self.entry_types.get(arg.arg)
            if propagated:
                state[arg.arg] = set(propagated)
                continue
            annotated = self._annotation_types(arg.annotation)
            if annotated:
                state[arg.arg] = annotated

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
            annotated = self._annotation_types(stmt.annotation)
            if stmt.value is not None:
                self._walk_expr(stmt.value, state)
                if isinstance(stmt.target, ast.Name):
                    self._update(state, stmt.target.id,
                                 self._eval_types(stmt.value, state) or annotated, conditional)
                elif isinstance(stmt.target, ast.Attribute):
                    self._update_attribute(stmt.target, self._eval_types(stmt.value, state) or annotated, state, conditional)
            elif annotated and isinstance(stmt.target, ast.Name):
                self._update(state, stmt.target.id, annotated, conditional)
            return state
        if isinstance(stmt, ast.AugAssign):
            self._walk_expr(stmt.value, state)
            self._assign_top(stmt.target, state)     # x += ... -> conservatively top
            return state
        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._walk_expr(stmt.value, state)
                types = self._eval_types(stmt.value, state)
                if types:
                    self.return_types.update(types)
                    self.return_type_facts.append(
                        {
                            "line_number": getattr(stmt, "lineno", 0),
                            "return_expr": self._call_expr(stmt.value),
                            "types": sorted(types),
                        }
                    )
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
            self._record_assignment_fact(node.targets[0].id, node.value, types, node)
        elif len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute):
            types = self._eval_types(node.value, state)
            self._update_attribute(node.targets[0], types, state, conditional)
            try:
                target_name = ast.unparse(node.targets[0])
            except Exception:
                target_name = ""
            if target_name:
                self._record_assignment_fact(target_name, node.value, types, node)
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
            self.call_arg_types[id(expr)] = [self._eval_types(arg, state) for arg in expr.args]
            if isinstance(func, ast.Attribute):
                try:
                    base = ast.unparse(func.value)
                except Exception:
                    base = ""
                current = self._eval_types(func.value, state) if isinstance(func.value, ast.Call) else state.get(base)
                # Concrete set if known, else None (= top: receiver type unknown).
                self.call_pt[id(expr)] = set(current) if current is not None else None
        for child in ast.iter_child_nodes(expr):
            self._walk_expr(child, state)

    # -- type evaluation of a right-hand side ---------------------

    def _eval_types(self, value: ast.expr, state: PointsToState) -> Optional[PointsToSet]:
        """The set of classes an assigned RHS may produce, or ``None`` for top."""
        if isinstance(value, ast.Call):
            modeled = self._resolve_external_call_return_types(value, state)
            if modeled is not None:
                return modeled or None
            ci = self._resolve_class_expr(value.func)
            if ci is not None:                       # constructor -> instance type
                return {ci.qualified}
            external = self._resolve_external_expr(value.func)
            if external is not None:
                modeled_direct = EXTERNAL_CALL_RETURN_TYPES.get(external)
                if modeled_direct is not None:
                    self._record_external_model(value, external, "call", modeled_direct)
                    return set(modeled_direct) or None
                if self._looks_like_constructor(external):
                    return {_type_external(external)}
                return {_type_factory(external)}
            fn = self._resolve_function_expr(value.func)
            if fn is not None:
                return self._infer_function_return_types(fn)
            call_name = _dotted_name(value.func) if isinstance(value.func, (ast.Name, ast.Attribute)) else ""
            return {_type_factory(call_name or "")}  # function return type unknown, but receiver methods are potential
        if isinstance(value, ast.Name):              # x = y -> copy pt(y)
            current = state.get(value.id)
            return set(current) if current is not None else None
        if isinstance(value, ast.Attribute):
            try:
                current = state.get(ast.unparse(value))
            except Exception:
                current = None
            return set(current) if current is not None else None
        return None                                  # literals/attrs/etc. -> top

    def _resolve_external_call_return_types(self, value: ast.Call, state: PointsToState) -> Optional[PointsToSet]:
        if not isinstance(value.func, ast.Attribute):
            return None
        receiver_types = self._eval_types(value.func.value, state)
        if not receiver_types:
            return None
        out: PointsToSet = set()
        matched = False
        for typ in receiver_types:
            if not _is_external_type(typ):
                continue
            external_type = _external_type_name(typ)
            key = (external_type, value.func.attr)
            if key not in EXTERNAL_METHOD_RETURN_TYPES:
                continue
            matched = True
            returns = EXTERNAL_METHOD_RETURN_TYPES[key]
            self._record_external_model(value, f"{external_type}.{value.func.attr}", "method", returns or set())
            if returns:
                out.update(returns)
        if not matched:
            return None
        return out

    def _record_external_model(self, node: ast.Call, target: str, kind: str, returns: PointsToSet) -> None:
        self.external_model_facts.append(
            {
                "target": target,
                "kind": kind,
                "line_number": getattr(node, "lineno", 0),
                "call_expr": self._call_expr(node),
                "return_types": sorted(returns),
                "reason": "deterministic external type model",
            }
        )

    def _record_assignment_fact(
        self,
        target: str,
        value: ast.AST,
        types: Optional[PointsToSet],
        node: ast.AST,
    ) -> None:
        if not types:
            return
        self.assignment_type_facts.append(
            {
                "target": target,
                "value_expr": self._call_expr(value),
                "line_number": getattr(node, "lineno", 0),
                "types": sorted(types),
            }
        )

    @staticmethod
    def _call_expr(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"

    def _resolve_class_expr(self, func: ast.expr) -> Optional[ClassInfo]:
        """Resolve a constructor expression (``Cls`` or ``mod.Cls``) to a class."""
        if isinstance(func, ast.Name):
            return self.scope.classes.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            dotted = self.scope.module_aliases.get(func.value.id)
            if dotted is not None:
                return self.index.resolve_class_dotted(f"{dotted}.{func.attr}")
        return None

    def _resolve_function_expr(self, func: ast.expr) -> Optional[FunctionNode]:
        if isinstance(func, ast.Name):
            return self.scope.local_funcs.get(func.id) or self.scope.imported_funcs.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            dotted = self.scope.module_aliases.get(func.value.id)
            if dotted is not None:
                return self.index.resolve_func_dotted(f"{dotted}.{func.attr}")
        return None

    def _resolve_external_expr(self, func: ast.expr) -> Optional[str]:
        if isinstance(func, ast.Name):
            ext = self.scope.external_funcs.get(func.id)
            if ext is not None:
                return ".".join(part for part in ext if part)
            module = self.scope.external_modules.get(func.id)
            return module
        if isinstance(func, ast.Attribute):
            try:
                base = ast.unparse(func.value)
            except Exception:
                base = ""
            dotted = ASTCandidateGenerator._resolve_module_alias(self.scope.external_modules, base)
            if dotted is not None:
                return ".".join(part for part in (dotted, func.attr) if part)
        return None

    @staticmethod
    def _looks_like_constructor(dotted: str) -> bool:
        leaf = dotted.rsplit(".", 1)[-1]
        return bool(leaf) and leaf[:1].isupper()

    def _infer_function_return_types(self, fn: FunctionNode) -> Optional[PointsToSet]:
        fn_name = fn.qualified_name or fn.function_name
        if fn_name in self.function_summaries:
            cached = self.function_summaries[fn_name].return_types
            return set(cached) if cached else None
        if fn_name in self.in_progress:
            return None
        func_def = self.index.function_defs.get(fn_name)
        if func_def is None:
            return None
        annotated = self._annotation_types(func_def.returns)
        if annotated:
            self.function_summaries[fn_name] = FunctionSummary(return_types=set(annotated))
            return annotated
        path = Path(fn.file_path)
        scope = self.index.scopes.get(path)
        if scope is None:
            return None
        enclosing = self._enclosing_for(fn)
        self.in_progress.add(fn_name)
        analyzer = AndersenPointsToAnalyzer(
            self.index,
            scope,
            enclosing,
            self.function_entry_types_for(fn_name),
            function_summaries=self.function_summaries,
            in_progress=self.in_progress,
        )
        analyzer.compute(func_def)
        self.in_progress.discard(fn_name)
        summary = FunctionSummary(
            param_types={key: set(value) for key, value in analyzer.entry_types.items()},
            return_types=set(analyzer.return_types),
            evidence=list(analyzer.return_type_facts),
        )
        self.function_summaries[fn_name] = summary
        return set(summary.return_types) if summary.return_types else None

    def function_entry_types_for(self, fn_name: str) -> Dict[str, PointsToSet]:
        return {}

    def _enclosing_for(self, fn: FunctionNode) -> Optional[ClassInfo]:
        fn_name = fn.qualified_name or fn.function_name
        for info in self.index.classes:
            for method in info.methods.values():
                if (method.qualified_name or method.function_name) == fn_name:
                    return info
        return None

    def _annotation_types(self, annotation: ast.expr | None) -> Optional[PointsToSet]:
        if annotation is None:
            return None
        dotted = _dotted_name(annotation)
        if dotted is None:
            return None
        resolved = self.scope.classes.get(dotted) or self.index.resolve_class_dotted(dotted)
        if resolved is not None:
            return {resolved.qualified}
        return None

    def _update_attribute(
        self,
        target: ast.Attribute,
        types: Optional[PointsToSet],
        state: PointsToState,
        conditional: bool,
    ) -> None:
        try:
            name = ast.unparse(target)
        except Exception:
            return
        self._update(state, name, types, conditional)

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

class CallGraphConstructionPipeline:
    """Shared per-function call graph construction pipeline.

    Both package and project modes use this object for the common core:

        AST + symbol/scope table -> import-aware candidates -> points-to facts
        -> call target resolution -> internal/external callees

    The mode-specific layers decide only which functions to feed into this
    pipeline: package analysis feeds every definition exhaustively, while project
    analysis feeds reachable definitions from a worklist.
    """

    def __init__(self, index: LibraryIndex) -> None:
        self.index = index
        self.unresolved_calls: List[UnresolvedCall] = []
        self.candidate_edges: List[CandidateEdge] = []
        self.llm_kept_edges: List[CandidateEdge] = []
        self.llm_pruned_edges: List[CandidateEdge] = []
        self.function_entry_types: Dict[str, Dict[str, PointsToSet]] = {}
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self._return_in_progress: Set[str] = set()
        self.parameter_type_facts: List[dict] = []
        self.assignment_type_facts: List[dict] = []
        self.return_type_facts: List[dict] = []
        self.external_model_facts: List[dict] = []
        self.edge_evidence: Dict[Tuple[str, str], dict] = {}
        self._resolved_unresolved: Set[Tuple[str, int, str]] = set()
        self._functions_by_name = {
            (fn.qualified_name or fn.function_name): fn
            for fn in self.index.functions
        }
        self._functions_by_simple_arity: Dict[Tuple[str, int], List[FunctionNode]] = {}
        for fn in self.index.functions:
            self._functions_by_simple_arity.setdefault((self._simple_name(fn), fn.arity), []).append(fn)
        self._classes_by_name_arity: Dict[Tuple[str, int], List[Tuple[ClassInfo, Optional[FunctionNode]]]] = {}
        for ci in self.index.classes:
            init = ci.methods.get("__init__")
            self._classes_by_name_arity.setdefault((ci.name, init.arity if init is not None else 0), []).append((ci, init))

    def analyze_definition(
        self,
        caller: FunctionNode,
        func_def: _FuncDef,
        scope: ModuleScope,
        enclosing: Optional[ClassInfo],
    ) -> List[FunctionNode]:
        generator = ASTCandidateGenerator(self.index, scope, enclosing)
        sites = generator.generate(func_def)
        self._record_unresolved(caller, generator.unresolved)

        analyzer = AndersenPointsToAnalyzer(
            self.index,
            scope,
            enclosing,
            self.function_entry_types.get(caller.qualified_name or caller.function_name),
            function_summaries=self.function_summaries,
            in_progress=self._return_in_progress,
        )
        pt = analyzer.compute(func_def)
        caller_name = caller.qualified_name or caller.function_name
        self.assignment_type_facts.extend(
            {**fact, "function": caller_name}
            for fact in analyzer.assignment_type_facts
        )
        self.return_type_facts.extend(
            {**fact, "function": caller_name}
            for fact in analyzer.return_type_facts
        )
        self.external_model_facts.extend(
            {**fact, "function": caller_name}
            for fact in analyzer.external_model_facts
        )
        self.function_summaries[caller_name] = FunctionSummary(
            param_types={key: set(value) for key, value in analyzer.entry_types.items()},
            return_types=set(analyzer.return_types),
            evidence=list(analyzer.return_type_facts),
        )
        callees: List[FunctionNode] = []
        for site_id, cands in sites.items():
            resolved = self.resolve_call_site(cands, pt.get(site_id))
            for callee in resolved:
                self._record_edge_evidence(caller, callee, self._evidence_for(callee, cands))
            self._record_parameter_flows(caller, resolved, analyzer.call_arg_types.get(site_id, []))
            callees.extend(resolved)
        for site_id, node in generator.unresolved.items():
            unresolved = self._unresolved_call(caller, node)
            pattern = self._pattern_candidates(unresolved, node, pt.get(site_id))
            for callee, evidence in pattern:
                self._record_edge_evidence(caller, callee, evidence)
                if evidence.get("resolver") == "external_type_model":
                    self.external_model_facts.append(
                        {
                            "function": caller_name,
                            "target": getattr(callee, "identity_string", "") or (callee.qualified_name or callee.function_name),
                            "kind": "method",
                            "line_number": evidence.get("line_number", 0),
                            "call_expr": evidence.get("call_expr", ""),
                            "return_types": list(evidence.get("return_types", [])),
                            "reason": "deterministic external type model",
                        }
                    )
                callees.append(callee)
            if pattern:
                self._resolved_unresolved.add(self._unresolved_key(unresolved))
        return callees

    def _record_edge_evidence(self, caller: FunctionNode, callee: FunctionNode, evidence: dict) -> None:
        caller_name = caller.qualified_name or caller.function_name
        callee_name = callee.qualified_name or callee.function_name
        allowed = {"edge_type", "confidence", "resolver", "reason", "call_expr", "line_number"}
        self.edge_evidence[(caller_name, callee_name)] = {
            key: value for key, value in evidence.items() if key in allowed
        }

    def _evidence_for(self, callee: FunctionNode, candidates: List[Candidate]) -> dict:
        for candidate in candidates:
            if candidate.callee == callee:
                return self._candidate_evidence(candidate)
        return {
            "edge_type": "confirmed_static",
            "confidence": 1.0,
            "resolver": "static",
            "reason": "statically resolved call target",
            "call_expr": "",
            "line_number": 0,
        }

    @staticmethod
    def _candidate_evidence(candidate: Candidate) -> dict:
        try:
            call_expr = ast.unparse(candidate.call_node)
        except Exception:
            call_expr = ""
        return {
            "edge_type": candidate.edge_type,
            "confidence": candidate.confidence,
            "resolver": candidate.resolver,
            "reason": candidate.reason,
            "call_expr": call_expr,
            "line_number": getattr(candidate.call_node, "lineno", 0),
        }

    def _pattern_candidates(
        self,
        unresolved: UnresolvedCall,
        node: ast.Call,
        receiver_pt: Optional[PointsToSet],
    ) -> List[Tuple[FunctionNode, dict]]:
        if not unresolved.call_name or not isinstance(node.func, ast.Attribute):
            return []
        method = unresolved.call_name
        out: List[Tuple[FunctionNode, dict]] = []
        if receiver_pt:
            for typ in sorted(receiver_pt):
                if _is_external_type(typ):
                    target = _external_type_name(typ)
                    model_key = (target, method)
                    resolver = "external_type_model" if model_key in EXTERNAL_METHOD_RETURN_TYPES else "external_constructor_receiver"
                    reason = (
                        f"method resolved using deterministic external type model for {target}"
                        if resolver == "external_type_model"
                        else f"receiver propagated from external constructor {target}"
                    )
                    confidence = 0.95 if resolver == "external_type_model" else 0.8
                    returns = EXTERNAL_METHOD_RETURN_TYPES.get(model_key) or set()
                    out.append(
                        (
                            _make_external_node(target, method, unresolved.line_number),
                            {
                                **self._pattern_evidence(
                                unresolved,
                                "confirmed_type",
                                resolver,
                                reason,
                                confidence,
                                ),
                                "return_types": sorted(returns),
                            },
                        )
                    )
                elif typ.startswith("factory:"):
                    out.append(
                        (
                            _make_external_node("", method, unresolved.line_number),
                            self._pattern_evidence(
                                unresolved,
                                "potential_pattern",
                                "factory_unknown_receiver",
                                f"receiver comes from unknown factory {typ.split(':', 1)[1]}",
                                0.45,
                            ),
                        )
                    )
        if out:
            return out
        if "(" in unresolved.receiver or "." in unresolved.receiver:
            return [
                (
                    _make_external_node("", method, unresolved.line_number),
                    self._pattern_evidence(
                        unresolved,
                        "potential_pattern",
                        "fluent_chain",
                        "method call appears in a fluent or chained expression",
                        0.4,
                    ),
                )
            ]
        if unresolved.receiver:
            return [
                (
                    _make_external_node("", method, unresolved.line_number),
                    self._pattern_evidence(
                        unresolved,
                        "potential_pattern",
                        "unknown_receiver_method",
                        "method call on an unknown receiver is retained as a conservative boundary candidate",
                        0.25,
                    ),
                )
            ]
        return []

    @staticmethod
    def _pattern_evidence(
        unresolved: UnresolvedCall,
        edge_type: str,
        resolver: str,
        reason: str,
        confidence: float,
    ) -> dict:
        return {
            "edge_type": edge_type,
            "confidence": confidence,
            "resolver": resolver,
            "reason": reason,
            "call_expr": unresolved.call_expr,
            "line_number": unresolved.line_number,
        }

    def _record_parameter_flows(
        self,
        caller: FunctionNode,
        callees: List[FunctionNode],
        arg_types: List[Optional[PointsToSet]],
    ) -> None:
        if not arg_types:
            return
        caller_name = caller.qualified_name or caller.function_name
        for callee in callees:
            if callee.is_external:
                continue
            callee_name = callee.qualified_name or callee.function_name
            params = self.index.function_params.get(callee_name, [])
            if not params:
                continue
            entry = self.function_entry_types.setdefault(callee_name, {})
            for param, types in zip(params, arg_types):
                if not types:
                    continue
                before = set(entry.get(param, set()))
                entry.setdefault(param, set()).update(types)
                if entry[param] != before:
                    self.parameter_type_facts.append(
                        {
                            "caller": caller_name,
                            "callee": callee_name,
                            "parameter": param,
                            "types": sorted(types),
                            "reason": "argument propagated from callsite",
                        }
                    )

    def _record_unresolved(self, caller: FunctionNode, calls: Dict[int, ast.Call]) -> None:
        for node in calls.values():
            unresolved = self._unresolved_call(caller, node)
            self.unresolved_calls.append(unresolved)
            self.candidate_edges.extend(self._coarse_candidates(unresolved))

    @staticmethod
    def _unresolved_key(unresolved: UnresolvedCall) -> Tuple[str, int, str]:
        return (unresolved.caller, unresolved.line_number, unresolved.call_expr)

    def _unresolved_call(self, caller: FunctionNode, node: ast.Call) -> UnresolvedCall:
        call_name, receiver = self._call_name_and_receiver(node)
        return UnresolvedCall(
            caller=caller.qualified_name or caller.function_name,
            file_path=str(caller.file_path),
            line_number=getattr(node, "lineno", 0),
            call_expr=self._call_expr(node),
            call_name=call_name,
            receiver=receiver,
            arity=len(node.args) + len(node.keywords),
        )

    def _coarse_candidates(self, unresolved: UnresolvedCall) -> List[CandidateEdge]:
        if not unresolved.call_name:
            return []
        out: List[CandidateEdge] = []
        caller = self._functions_by_name.get(unresolved.caller)

        for fn in self._functions_by_simple_arity.get((unresolved.call_name, unresolved.arity), []):
            out.append(
                self._candidate_edge(
                    unresolved,
                    fn.qualified_name or fn.function_name,
                    "coarse_name_arity",
                    "matched unresolved call by simple function/method name and arity",
                    caller=caller,
                    callee=fn,
                    confidence=0.35,
                )
            )

        for ci, init in self._classes_by_name_arity.get((unresolved.call_name, unresolved.arity), []):
            out.append(
                self._candidate_edge(
                    unresolved,
                    ci.qualified,
                    "coarse_class_name_arity",
                    "matched unresolved constructor call by class name and arity",
                    caller=caller,
                    callee=init,
                    confidence=0.35,
                )
            )

        out = self._dedupe_candidates(out)
        if len(out) > CANDIDATE_FANOUT_CAP:
            return [
                CandidateEdge(
                    caller=unresolved.caller,
                    callee="",
                    file_path=unresolved.file_path,
                    line_number=unresolved.line_number,
                    call_expr=unresolved.call_expr,
                    confidence=0.0,
                    resolver="coarse_name_arity",
                    status="too_many_candidates",
                    reason=(
                        f"candidate fanout {len(out)} exceeds cap "
                        f"{CANDIDATE_FANOUT_CAP}; refine statically or with a narrower query"
                    ),
                    arity=unresolved.arity,
                    receiver=unresolved.receiver,
                    caller_signature=caller.signature if caller is not None else "",
                    caller_source=caller.source_snippet if caller is not None else "",
                )
            ]
        return out

    @staticmethod
    def _dedupe_candidates(candidates: List[CandidateEdge]) -> List[CandidateEdge]:
        seen: Set[Tuple[str, str, int, str]] = set()
        out: List[CandidateEdge] = []
        for candidate in candidates:
            key = (candidate.caller, candidate.callee, candidate.line_number, candidate.call_expr)
            if key in seen:
                continue
            seen.add(key)
            out.append(candidate)
        return out

    def _candidate_edge(
        self,
        unresolved: UnresolvedCall,
        callee_name: str,
        resolver: str,
        reason: str,
        *,
        caller: Optional[FunctionNode],
        callee: Optional[FunctionNode],
        confidence: float,
    ) -> CandidateEdge:
        return CandidateEdge(
            caller=unresolved.caller,
            callee=callee_name,
            file_path=unresolved.file_path,
            line_number=unresolved.line_number,
            call_expr=unresolved.call_expr,
            confidence=confidence,
            resolver=resolver,
            reason=reason,
            arity=unresolved.arity,
            receiver=unresolved.receiver,
            caller_signature=caller.signature if caller is not None else "",
            callee_signature=callee.signature if callee is not None else "",
            caller_source=caller.source_snippet if caller is not None else "",
            callee_source=callee.source_snippet if callee is not None else "",
        )

    @staticmethod
    def _simple_name(node: FunctionNode) -> str:
        name = node.qualified_name or node.function_name
        return name.rsplit(".", 1)[-1]

    @staticmethod
    def _call_expr(node: ast.Call) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return "<call>"

    @staticmethod
    def _call_name_and_receiver(node: ast.Call) -> Tuple[str, str]:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id, ""
        if isinstance(func, ast.Attribute):
            receiver = ""
            if isinstance(func.value, ast.Name):
                receiver = func.value.id
            else:
                try:
                    receiver = ast.unparse(func.value)
                except Exception:
                    receiver = ""
            return func.attr, receiver
        return "", ""

    def resolve_call_site(
        self,
        cands: List[Candidate],
        receiver_pt: Optional[PointsToSet],
    ) -> List[FunctionNode]:
        """Resolve one call site's candidate set using Layer-2 points-to facts."""
        keep: List[FunctionNode] = [c.callee for c in cands if not c.prunable]
        prunable = [c for c in cands if c.prunable]
        if not prunable:
            return keep

        call_node = prunable[0].call_node
        if receiver_pt is None:
            resolved = self.resolve_dynamic_call(call_node)
            if resolved is not None:
                keep.append(resolved)
            else:
                keep.extend(c.callee for c in prunable)
            return keep

        matched = [c.callee for c in prunable if c.owner in receiver_pt]
        if matched:
            keep.extend(matched)
        else:
            resolved = self.resolve_dynamic_call(call_node)
            if resolved is not None:
                keep.append(resolved)
        return keep

    def resolve_dynamic_call(self, call_node: ast.Call) -> Optional[FunctionNode]:
        """Future hook for InferCG-style semantic pruning or LLM disambiguation."""
        return None

    def report(self) -> dict:
        unresolved = [
            item
            for item in self.unresolved_calls
            if self._unresolved_key(item) not in self._resolved_unresolved
        ]
        external_model_facts = self._dedupe_dicts(self.external_model_facts)
        return {
            "unresolved_calls": [vars(item) for item in unresolved],
            "candidate_edges": [vars(item) for item in self.candidate_edges],
            "llm_kept_edges": [vars(item) for item in self.llm_kept_edges],
            "llm_pruned_edges": [vars(item) for item in self.llm_pruned_edges],
            "parameter_type_facts": list(self.parameter_type_facts),
            "assignment_type_facts": list(self.assignment_type_facts),
            "return_type_facts": list(self.return_type_facts),
            "external_model_facts": external_model_facts,
            "function_summaries": {
                name: {
                    "param_types": {key: sorted(value) for key, value in summary.param_types.items()},
                    "return_types": sorted(summary.return_types),
                }
                for name, summary in sorted(self.function_summaries.items())
            },
            "unresolved_public_exports": self.index.public_export_warnings(),
        }

    @staticmethod
    def _dedupe_dicts(items: List[dict]) -> List[dict]:
        seen: Set[Tuple[Tuple[str, str], ...]] = set()
        out: List[dict] = []
        for item in items:
            key = tuple(sorted((str(k), str(v)) for k, v in item.items()))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out


class LibraryAnalyzer:
    """Coordinate exhaustive indexing, candidate generation and points-to pruning
    into a single library call graph (G_L)."""

    def __init__(self) -> None:
        self.index: Optional[LibraryIndex] = None
        self.pipeline: Optional[CallGraphConstructionPipeline] = None
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
        self.pipeline = CallGraphConstructionPipeline(self.index)
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
                    assert self.pipeline is not None
                    callees = self.pipeline.analyze_definition(caller, func_def, scope, enclosing)
                except Exception as exc:    # one bad definition never kills build
                    logger.warning("[LibGraph] Failed to analyze %s in %s: %s",
                                   caller.function_name, path, exc)
                    continue
                for callee in callees:
                    graph.add_node(callee)
                    key = (caller, callee)
                    if key not in self._seen_edges:
                        self._seen_edges.add(key)
                        evidence = self.pipeline.edge_evidence.get(
                            (caller.qualified_name or caller.function_name, callee.qualified_name or callee.function_name),
                            {},
                        )
                        graph.edges.append(CallEdge(caller=caller, callee=callee, **evidence))

        logger.info("[LibGraph] Built G_L: %d node(s), %d edge(s)",
                    len(graph.nodes), len(graph.edges))
        if self.pipeline is not None:
            graph.metadata.update(self.pipeline.report())
        graph.metadata["skipped_files"] = list(self.index.skipped_files)
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
        assert self.pipeline is not None
        # Compatibility wrapper for older callers; reports use a synthetic caller.
        caller = FunctionNode(
            file_path=str(scope.file_path),
            function_name=getattr(func_def, "name", "<unknown>"),
            qualified_name=getattr(func_def, "name", "<unknown>"),
            line_number=getattr(func_def, "lineno", 0),
        )
        return self.pipeline.analyze_definition(caller, func_def, scope, enclosing)



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
