"""
Phase 4 — the Compositional Query Engine.

This module composes the per-library Phase 2 summaries (``S_i`` / ``S_o``) into a
single transitive, cross-TPL reachability answer. Given:

  * the **Usage Index** (``ui``) — the set of external symbols the *project
    itself* calls, each an :class:`~pyshare.core.models.ExternalNode`;
  * a map of **library summaries** keyed by root library name; and
  * a set of **vulnerabilities** (qualified sink / vulnerable-function names),

it performs a path-aware breadth-first search over the supply chain and reports
every concrete path that lands on a known vulnerability.

Design notes that the four critical requirements pin down:

1. **The Direct-Sink blind spot.** A hop may *be* the vulnerability itself —
   e.g. the project (or a TPL) calls ``os.system`` directly. The standard
   library has no :class:`LibrarySummary`, so a summary lookup would silently
   drop it. Every hop is therefore tested against ``vulnerabilities`` *before*
   any summary is consulted.
2. **Sinks live in both summaries.** A vulnerability can be a first-party
   function reached intra-library (S_i) *or* a cross-library symbol the API
   reaches (S_o). Both are intersected against ``vulnerabilities``.
3. **Path-aware BFS.** The queue stores ``(current_target, path_so_far)`` so the
   exact supply-chain trace can be reconstructed for the report.
4. **Routing + longest-suffix matching.** The root module of a dotted target
   selects its :class:`LibrarySummary`; the precise API key inside that summary
   is then resolved by longest dotted-suffix match, tolerating partial
   qualification differences between how a symbol is *referenced* and how it is
   *keyed*.

All vulnerability tests in the hot path are strict ``set`` operations
(``in`` / ``&``), i.e. O(1) per element.
"""
from collections import deque
from typing import Deque, Dict, List, Optional, Set, Tuple

from pyshare.core.models import (
    ExternalNode,
    LibrarySummary,
    QueryReport,
    ReachabilityPath,
)

# A BFS work item: the dotted symbol we are currently exploring, and the full
# ordered chain of hops that led us there (its first element is the project API).
_QueueItem = Tuple[str, List[str]]


class ReachabilityQueryEngine:
    """
    Answers "does the project reach a vulnerable function?" by walking the
    composed S_i / S_o summaries across TPL boundaries.

    Parameters
    ----------
    ui:
        The Phase 3 Usage Index — every external call the project makes. Each
        node's :pyattr:`~pyshare.core.models.ExternalNode.identity_string`
        (``target_module.target_name``) seeds the search and matches how S_o
        renders reachable targets, so hops chain together by plain strings.
    summaries:
        Maps a **root library name** (e.g. ``"fastapi"``) to its precomputed
        :class:`LibrarySummary`. Lookups are routed by the root module of the
        dotted target currently under inspection.
    vulnerabilities:
        Qualified names of known-vulnerable functions / sinks. Membership and
        intersection against this set is what flags a path as dangerous.
    """

    def __init__(
        self,
        ui: List[ExternalNode],
        summaries: Dict[str, LibrarySummary],
        vulnerabilities: Set[str],
    ) -> None:
        self.ui = ui
        self.summaries = summaries
        self.vulnerabilities = vulnerabilities

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def check_reachability(self) -> QueryReport:
        """
        Run the path-aware BFS from every Usage-Index entry point and collect
        all concrete paths that reach a known vulnerability.

        Returns a :class:`QueryReport` whose ``is_vulnerable`` flag is ``True``
        iff at least one such path exists.
        """
        paths: List[ReachabilityPath] = []
        visited: Set[str] = set()
        queue: Deque[_QueueItem] = deque()

        # Seed the frontier with the project's own external calls. Each UI node
        # is a *project API* — the head of any chain it begins.
        for ui_node in self.ui:
            start = ui_node.identity_string
            if start in visited:
                continue
            visited.add(start)
            queue.append((start, [start]))

        while queue:
            current_target, current_path = queue.popleft()

            # ---- Step 1: Direct vulnerability check (the blind-spot guard). --
            # The hop may itself be a sink with no LibrarySummary (stdlib, C
            # extensions, ...). Test it *before* any routing so such sinks are
            # never lost. Suffix matching tolerates qualification differences.
            direct_vuln = self._match_vulnerability(current_target)
            if direct_vuln is not None:
                paths.append(self._make_path(current_path, direct_vuln))
                # The target is terminal-as-a-sink; nothing further to expand
                # for *this* node along the vulnerability dimension.
                continue

            # ---- Step 2: Library routing. -----------------------------------
            root = self._root_module(current_target)
            summary = self.summaries.get(root)
            if summary is None:
                # No summary for this library — cannot expand further. (Any
                # vulnerability it directly *is* was already caught in Step 1.)
                continue

            # ---- Step 3: Resolve the API key. -------------------------------
            api_key = self._resolve_api_key(current_target, summary)
            if api_key is None:
                continue

            inner_reach: Set[str] = summary.inner_summary.get(api_key, set())
            outer_reach: Set[str] = summary.outer_summary.get(api_key, set())

            # ---- Step 4: Summary intersections (strict O(1) set ops). -------
            # A vulnerability may be reached intra-library (S_i) or across a TPL
            # boundary (S_o). Intersect against both; every hit is a witness.
            for vuln in (inner_reach & self.vulnerabilities):
                paths.append(self._make_path(current_path, vuln))
            for vuln in (outer_reach & self.vulnerabilities):
                paths.append(self._make_path(current_path, vuln))

            # ---- Step 5: Enqueue next hops. ---------------------------------
            # Only *external* targets (S_o) cross into other libraries and thus
            # continue the supply chain. Skip ones already flagged as vulns
            # (recorded above) and ones already visited.
            for next_hop in (outer_reach - self.vulnerabilities):
                if next_hop in visited:
                    continue
                visited.add(next_hop)
                queue.append((next_hop, current_path + [next_hop]))

        return QueryReport(is_vulnerable=bool(paths), paths=paths)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _root_module(dotted: str) -> str:
        """Root package of a dotted name: ``"werkzeug.serving.run_simple" -> "werkzeug"``."""
        return dotted.split(".", 1)[0]

    @staticmethod
    def _suffix_overlap(a: str, b: str) -> int:
        """
        Number of trailing **dotted components** ``a`` and ``b`` share.

        Comparison is component-aligned (not character-wise) so that
        ``"json.loads"`` and ``"x.loads"`` overlap by exactly one component
        (``loads``), while ``"json.loads"`` and ``"y.dumps"`` overlap by zero.
        """
        ap = a.split(".")
        bp = b.split(".")
        n = 0
        for x, y in zip(reversed(ap), reversed(bp)):
            if x != y:
                break
            n += 1
        return n

    def _match_vulnerability(self, target: str) -> Optional[str]:
        """
        Return the vulnerability ``target`` corresponds to, or ``None``.

        Fast path is an O(1) exact set membership test. Only when that misses do
        we fall back to a longest-suffix scan, so qualification mismatches
        (e.g. ``"a.b.os.system"`` vs. a recorded ``"os.system"``) still resolve.
        The fallback requires a *full* suffix containment on a component
        boundary, never a mere partial-component overlap.
        """
        if target in self.vulnerabilities:
            return target

        best: Optional[str] = None
        best_score = 0
        for vuln in self.vulnerabilities:
            # Require one string to be a component-aligned suffix of the other.
            if not (target == vuln
                    or target.endswith("." + vuln)
                    or vuln.endswith("." + target)):
                continue
            score = self._suffix_overlap(target, vuln)
            if score > best_score:
                best, best_score = vuln, score
        return best

    def _resolve_api_key(self, target: str, summary: LibrarySummary) -> Optional[str]:
        """
        Longest-suffix match of ``target`` against the summary's API keys.

        The same logical symbol may be *referenced* and *keyed* with different
        leading qualification (how it was imported vs. how the indexer recorded
        it). We pick the key sharing the longest dotted suffix with ``target``,
        considering keys from both S_i and S_o. Returns ``None`` when nothing
        overlaps.
        """
        exact = (target in summary.inner_summary) or (target in summary.outer_summary)
        if exact:
            return target

        best: Optional[str] = None
        best_score = 0
        # Union of both summaries' keys — an API may have only inner, only
        # outer, or both reach-sets recorded.
        for key in (summary.inner_summary.keys() | summary.outer_summary.keys()):
            if not (target == key
                    or target.endswith("." + key)
                    or key.endswith("." + target)):
                continue
            score = self._suffix_overlap(target, key)
            if score > best_score:
                best, best_score = key, score
        return best

    @staticmethod
    def _make_path(current_path: List[str], vuln: str) -> ReachabilityPath:
        """
        Build a :class:`ReachabilityPath` from the BFS chain and matched sink.

        ``tpl_chain`` is the full ordered trace ending at ``vuln``; when the
        vulnerability *is* the current hop (a direct sink) it is already the
        tail, so we avoid duplicating it.
        """
        chain = list(current_path)
        if not chain or chain[-1] != vuln:
            chain.append(vuln)
        return ReachabilityPath(
            project_api=chain[0],
            tpl_chain=chain,
            vulnerable_target=vuln,
        )
