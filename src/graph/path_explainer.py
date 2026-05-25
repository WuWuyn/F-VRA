"""Explain HOW a vulnerable function is reachable -- shortest path output.

Use only when reachability has already been confirmed; this is the
expensive query (BFS shortestPath through the entire graph).
"""
from __future__ import annotations

from typing import Optional

import neo4j

from pyshare.graph import db_provider


_SHORTEST_PATH = """
MATCH path = shortestPath(
  (e:Function {project_id: $project_id, commit_sha: $commit_sha, qname: $entry_qname})
  -[:CALLS*1..%d]->
  (v:Function {project_id: $project_id, commit_sha: $commit_sha, qname: $vf_qname})
)
RETURN [n IN nodes(path) | {qname: n.qname, kind: n.kind}] AS chain
LIMIT 1
"""


def explain(
    project_id: str,
    commit_sha: str,
    entry_qname: str,
    vf_qname: str,
    *,
    max_depth: int = 30,
    driver: Optional[neo4j.Driver] = None,
) -> Optional[list[dict[str, str]]]:
    """Return the shortest call chain from entry to vf, or None if unreachable.

    Each chain element: {"qname": str, "kind": str}.
    Bounded by max_depth -- important since shortestPath without bound
    can stall on large cyclic graphs.
    """
    drv = driver or db_provider.connect()
    with drv.session() as session:
        result = session.execute_read(
            lambda tx: tx.run(
                _SHORTEST_PATH % max_depth,
                project_id=project_id,
                commit_sha=commit_sha,
                entry_qname=entry_qname,
                vf_qname=vf_qname,
            ).single()
        )
    if not result or not result["chain"]:
        return None
    return [{"qname": n["qname"], "kind": n["kind"]} for n in result["chain"]]
