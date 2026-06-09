"""
Phase 4 — the Compositional Query Engine.

Consumes the Phase 2 :class:`~pyshare.core.models.LibrarySummary` matrices
(S_i / S_o) and the Phase 3 Usage Index to answer the end-to-end reachability
question: *does this project reach a known vulnerable function across the TPL
supply chain?*
"""
from pyshare.pipeline.query_engine.engine import ReachabilityQueryEngine

__all__ = ["ReachabilityQueryEngine"]
