"""
pcsg_indexer.indexer
════════════════════
Phase 2 of the PyShare framework — **Transitive Closure Indexing**.

``library_builder`` (Phase 1) hands us a precise but verbose
:class:`~pyshare_core.models.CallGraph`: every first-party
:class:`~pyshare_core.models.FunctionNode`, every cross-TPL-boundary
:class:`~pyshare_core.models.ExternalNode`, and the points-to-refined call
edges between them. Answering "is X reachable from public API Y?" by walking
that graph on every query is wasteful. This module instead pre-computes the
**transitive closure** (``G_L^+``) once and compresses it into a
:class:`~pyshare_core.models.LibrarySummary`, so later phases answer reachability
with an O(1) set lookup.

Why ``scipy.sparse``
--------------------
A real library call graph is large (tens of thousands of nodes) but *sparse* —
each function calls only a handful of others, so the adjacency matrix has a tiny
fraction of its ``N×N`` cells filled. Storing it as a dense matrix would cost
``N²`` bytes (gigabytes for a big library); a **CSR (Compressed Sparse Row)**
matrix stores only the non-zeros, keeping the footprint to a few MBs and giving
:mod:`scipy.sparse.csgraph` a cache-friendly layout for fast traversal. CSR is
mandatory here for exactly that enterprise-scalability reason.

Why per-API BFS rather than a full ``N×N`` closure
--------------------------------------------------
The mathematically tidy object is the full ``N×N`` boolean reachability matrix,
obtainable by repeated boolean squaring of the adjacency matrix
(``R = A | A² | A³ | …`` until it stabilises). But that closure is frequently
*dense* even when the graph is sparse (one widely-reachable utility makes a whole
column dense), which would blow the memory budget the CSR layout exists to
protect. Since the summary only ever needs the closure rows for the **public
APIs** — not for every internal node — we instead run a directed
breadth-first traversal (:func:`scipy.sparse.csgraph.breadth_first_order`) from
each API over the CSR adjacency. Each traversal materialises exactly one
closure row (the reach-set of that API) and nothing more, so peak memory stays
proportional to the largest single reach-set, not to ``N²``. The collected rows
are assembled into a sparse ``(num_api × N)`` closure matrix — the relevant
slice of ``G_L^+`` — which is what the summaries are read off of.
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Deque, Dict, List, Optional, Sequence

import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import breadth_first_order

from pyshare_core.models import (
    CallGraph,
    ExternalNode,
    FunctionNode,
    LibrarySummary,
)

logger = logging.getLogger(__name__)


def _node_sort_key(node: FunctionNode) -> tuple:
    """Deterministic ordering key for assigning integer indices to nodes.

    ``CallGraph.nodes`` is a ``set`` (no stable iteration order across runs).
    We materialise a reproducible index map so the adjacency matrix — and any
    artefact derived from it — is byte-for-byte stable for the same graph, which
    matters for caching and for debuggable ``.npz`` dumps. Internal nodes sort
    before external ones; ties break on the dotted names so the order is
    human-readable.
    """
    return (node.is_external, node.qualified_name, node.file_path,
            node.function_name)


def _external_target(node: ExternalNode) -> str:
    """Render an :class:`ExternalNode` as its dotted ``module.name`` target.

    This is the canonical S_o identity for a cross-TPL edge: the symbol the
    library actually reaches into (``"werkzeug.serving"`` + ``"run_simple"`` →
    ``"werkzeug.serving.run_simple"``). Either component may be empty, so we drop
    blanks rather than emit a stray leading/trailing dot.
    """
    return ".".join(part for part in (node.target_module, node.target_name)
                    if part)


def _render_node(node: FunctionNode) -> str:
    if isinstance(node, ExternalNode):
        return _external_target(node)
    return node.qualified_name or node.function_name


def _api_key(api: FunctionNode) -> str:
    """The summary dictionary key for a public API — its ``qualified_name``,
    falling back to ``function_name`` for the rare node that carries no dotted
    path (keeps the key non-empty and stable)."""
    return api.qualified_name or api.function_name


class PCSGIndexer:
    """Compress a library :class:`CallGraph` into a :class:`LibrarySummary`.

    Workflow (see module docstring for the *why*):

      1. **Index** every node to a contiguous integer (``_build_index``).
      2. **Construct** the boolean CSR adjacency matrix from the call edges
         (``_build_adjacency``).
      3. **Close** the graph by running a directed BFS from each public API over
         the CSR adjacency, assembling the public-API rows of ``G_L^+`` into a
         sparse closure matrix (``_build_closure``).
      4. **Extract** the inner (S_i) / outer (S_o) summaries from the closure,
         strictly partitioning first-party reach from cross-TPL reach
         (``_extract_summary``).

    Parameters
    ----------
    graph:
        The library call graph produced by Phase 1.
    public_apis:
        The public API surface to summarise. Nodes not present in *graph*
        are reported and skipped rather than treated as fatal.
    """

    def __init__(self, graph: CallGraph, public_apis: Sequence[FunctionNode]) -> None:
        self.graph = graph
        self.public_apis = list(public_apis)

        # Populated by build().
        self._nodes: List[FunctionNode] = []            # index -> node
        self._index: Dict[FunctionNode, int] = {}       # node  -> index
        self._adjacency: Optional[csr_matrix] = None    # N×N boolean, caller->callee

    # ── public entry point ───────────────────────────────────────────────

    def build(self) -> LibrarySummary:
        """Run the full index → matrix → closure → summary pipeline."""
        self._build_index()
        if not self._nodes:
            logger.info("[PCSG] Empty graph — nothing to index.")
            return LibrarySummary()

        self._adjacency = self._build_adjacency()

        api_indices = self._resolve_api_indices()
        if not api_indices:
            logger.info("[PCSG] No public APIs resolved against the graph.")
            return LibrarySummary()

        closure = self._build_closure(api_indices)
        summary = self._extract_summary(api_indices, closure)

        logger.info(
            "[PCSG] Indexed %d node(s), %d edge(s) -> %d API summary(ies) "
            "(S_i + S_o)",
            len(self._nodes), int(self._adjacency.nnz), len(summary.inner_summary),
        )
        return summary

    # ── step 1: integer indexing ─────────────────────────────────────────

    def _build_index(self) -> None:
        """Map every node to a contiguous integer index (and back).

        The two-way map (``_nodes`` list + ``_index`` dict) is the bridge
        between graph objects and matrix coordinates. Lookups go through
        :class:`FunctionNode` identity (``__hash__``/``__eq__``), so an edge that
        references a distinct-but-equal node instance still resolves to the same
        column — and an :class:`ExternalNode`'s 3-tuple identity can never
        collide with a :class:`FunctionNode`'s 2-tuple identity.
        """
        self._nodes = sorted(self.graph.nodes, key=_node_sort_key)
        self._index = {node: i for i, node in enumerate(self._nodes)}

    # ── step 2: CSR adjacency construction ────────────────────────────────

    def _build_adjacency(self) -> csr_matrix:
        """Build the boolean ``N×N`` adjacency matrix in CSR form.

        ``A[i, j] = True`` iff node ``i`` (caller) calls node ``j`` (callee).
        We accumulate coordinate triplets and let SciPy assemble the CSR matrix
        directly, summing duplicate ``(i, j)`` entries (parallel edges) into a
        single non-zero — ``dtype=bool`` keeps every cell a clean 0/1. Edges
        whose endpoints are somehow absent from the index are skipped defensively
        so a malformed graph degrades gracefully instead of raising.
        """
        n = len(self._nodes)
        rows: List[int] = []
        cols: List[int] = []
        skipped = 0
        for edge in self.graph.edges:
            i = self._index.get(edge.caller)
            j = self._index.get(edge.callee)
            if i is None or j is None:
                skipped += 1
                continue
            rows.append(i)
            cols.append(j)

        if skipped:
            logger.warning("[PCSG] Skipped %d edge(s) with unindexed endpoints.",
                           skipped)

        data = np.ones(len(rows), dtype=bool)
        matrix = csr_matrix(
            (data, (np.asarray(rows, dtype=np.int64),
                    np.asarray(cols, dtype=np.int64))),
            shape=(n, n),
            dtype=bool,
        )
        # Coalesce any duplicate coordinates into single boolean non-zeros.
        matrix.sum_duplicates()
        return matrix

    # ── step 3: transitive closure (G_L^+) over the public-API rows ───────

    def _resolve_api_indices(self) -> Dict[int, FunctionNode]:
        """Map each resolvable public API to its matrix index.

        De-duplicates APIs that collapse to the same node identity and reports
        any API node missing from the graph (the summary simply omits it).
        """
        resolved: Dict[int, FunctionNode] = {}
        missing = 0
        for api in self.public_apis:
            idx = self._index.get(api)
            if idx is None:
                missing += 1
                continue
            resolved.setdefault(idx, api)
        if missing:
            logger.warning("[PCSG] %d public API(s) not found in graph; skipped.",
                           missing)
        return resolved

    def _build_closure(self, api_indices: Dict[int, FunctionNode]) -> csr_matrix:
        """Assemble the public-API rows of the transitive closure ``G_L^+``.

        For each API index we run a directed BFS over the CSR adjacency; the set
        of visited nodes is exactly that API's reachability row (including the
        API itself — :meth:`_extract_summary` filters it out). Rows are returned
        as a sparse ``(num_api × N)`` CSR matrix, the only slice of the full
        ``N×N`` closure the summaries need — so memory tracks the reach-sets, not
        ``N²``.
        """
        assert self._adjacency is not None
        n = len(self._nodes)
        ordered = sorted(api_indices)                 # stable row order

        rows: List[int] = []
        cols: List[int] = []
        for row, src in enumerate(ordered):
            reachable = breadth_first_order(
                self._adjacency,
                i_start=src,
                directed=True,
                return_predecessors=False,
            )
            rows.extend([row] * len(reachable))
            cols.extend(int(c) for c in reachable)

        data = np.ones(len(rows), dtype=bool)
        return csr_matrix(
            (data, (np.asarray(rows, dtype=np.int64),
                    np.asarray(cols, dtype=np.int64))),
            shape=(len(ordered), n),
            dtype=bool,
        )

    # ── step 4: S_i / S_o summary extraction ──────────────────────────────

    def _shortest_paths_from(self, src: int) -> dict[int, list[int]]:
        """Return one deterministic witness path from *src* to each reachable node."""
        assert self._adjacency is not None
        queue: Deque[int] = deque([src])
        paths: dict[int, list[int]] = {src: [src]}

        while queue:
            node = queue.popleft()
            start, end = self._adjacency.indptr[node], self._adjacency.indptr[node + 1]
            for nxt in sorted(int(item) for item in self._adjacency.indices[start:end]):
                if nxt in paths:
                    continue
                paths[nxt] = [*paths[node], nxt]
                queue.append(nxt)
        return paths

    def _extract_summary(self, api_indices: Dict[int, FunctionNode],
                         closure: csr_matrix) -> LibrarySummary:
        """Read the inner (S_i) and outer (S_o) reach-sets off the closure rows.

        Row ``r`` of *closure* corresponds to the ``r``-th API in sorted-index
        order. For every node that row marks reachable we partition strictly:
        a first-party :class:`FunctionNode` (other than the API itself) feeds
        S_i with its ``qualified_name``; an :class:`ExternalNode` feeds S_o with
        its dotted ``module.name`` target. The two summaries never share an
        entry — first-party reach and cross-TPL reach stay disjoint by
        construction.
        """
        summary = LibrarySummary()
        ordered = sorted(api_indices)
        indptr, col_idx = closure.indptr, closure.indices

        for row, src in enumerate(ordered):
            api = api_indices[src]
            key = _api_key(api)
            inner = summary.inner_summary.setdefault(key, set())
            outer = summary.outer_summary.setdefault(key, set())
            inner_paths = summary.inner_paths.setdefault(key, {})
            outer_paths = summary.outer_paths.setdefault(key, {})
            paths_by_index = self._shortest_paths_from(src)

            # CSR row slice: the reachable column indices for this API.
            for j in col_idx[indptr[row]:indptr[row + 1]]:
                col = int(j)
                if col == src:
                    continue                          # exclude the API itself
                node = self._nodes[col]
                path = [_render_node(self._nodes[idx]) for idx in paths_by_index.get(col, [src, col])]
                if isinstance(node, ExternalNode):
                    target = _external_target(node)
                    outer.add(target)
                    outer_paths.setdefault(target, path)
                else:
                    target = node.qualified_name
                    inner.add(target)
                    inner_paths.setdefault(target, path)

        return summary


# ══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def build_library_summary(graph: CallGraph,
                          public_apis: Sequence[FunctionNode]) -> LibrarySummary:
    """Compress *graph* into a :class:`LibrarySummary` over *public_apis*.

    Convenience wrapper around :class:`PCSGIndexer` — the canonical Phase-2 entry
    point referenced by the rest of the PyShare pipeline.
    """
    return PCSGIndexer(graph, public_apis).build()
