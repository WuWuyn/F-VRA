"""Write/read project call graphs in Neo4j.

Operates on the typed CallGraph produced by
:mod:`pyshare.pipeline.project_scanner.jarvis_parser`. The graph layer
does NOT build call graphs — JARVIS does. This module only persists.
"""
from __future__ import annotations

from typing import Optional

import neo4j

from pyshare.graph import db_provider
from pyshare.pipeline.project_scanner.jarvis_parser import CallGraph


# Cypher templates ------------------------------------------------------

_MERGE_NODES = """
UNWIND $nodes AS n
MERGE (f:Function {project_id: $project_id, commit_sha: $commit_sha, qname: n.qname})
SET f.kind = n.kind, f.is_entry = n.is_entry
FOREACH (_ IN CASE WHEN n.is_entry THEN [1] ELSE [] END | SET f:EntryPoint)
"""

_MERGE_EDGES = """
UNWIND $edges AS e
MATCH (c:Function {project_id: $project_id, commit_sha: $commit_sha, qname: e.caller})
MATCH (t:Function {project_id: $project_id, commit_sha: $commit_sha, qname: e.callee})
MERGE (c)-[r:CALLS]->(t)
SET r.source = $source
"""

_DELETE_PROJECT = """
MATCH (f:Function {project_id: $project_id, commit_sha: $commit_sha})
DETACH DELETE f
RETURN count(f) AS deleted
"""

_EXISTS_PROJECT = """
MATCH (f:Function {project_id: $project_id, commit_sha: $commit_sha})
RETURN count(f) > 0 AS exists
"""

_COUNT_PROJECT = """
MATCH (f:Function {project_id: $project_id, commit_sha: $commit_sha})
RETURN count(f) AS node_count
"""


# Public API ------------------------------------------------------------

def write(
    cg: CallGraph,
    project_id: str,
    commit_sha: str,
    *,
    source: str = "jarvis",
    batch_size: int = 5000,
    driver: Optional[neo4j.Driver] = None,
) -> dict[str, int]:
    """Persist a CallGraph to Neo4j under (project_id, commit_sha)."""
    drv = driver or db_provider.connect()

    node_payload = [
        {"qname": n.qname, "kind": n.kind.value, "is_entry": n.is_entry}
        for n in cg.nodes.values()
    ]
    edge_payload = [
        {"caller": e.caller, "callee": e.callee} for e in cg.edges
    ]

    with drv.session() as session:
        for batch in _chunked(node_payload, batch_size):
            session.execute_write(
                lambda tx: tx.run(
                    _MERGE_NODES,
                    nodes=batch,
                    project_id=project_id,
                    commit_sha=commit_sha,
                ).consume()
            )
        for batch in _chunked(edge_payload, batch_size):
            session.execute_write(
                lambda tx: tx.run(
                    _MERGE_EDGES,
                    edges=batch,
                    project_id=project_id,
                    commit_sha=commit_sha,
                    source=source,
                ).consume()
            )

    return {"nodes_written": len(node_payload), "edges_written": len(edge_payload)}


def delete(
    project_id: str,
    commit_sha: str,
    *,
    driver: Optional[neo4j.Driver] = None,
) -> int:
    drv = driver or db_provider.connect()
    with drv.session() as session:
        result = session.execute_write(
            lambda tx: tx.run(
                _DELETE_PROJECT,
                project_id=project_id,
                commit_sha=commit_sha,
            ).single()
        )
    return int(result["deleted"]) if result else 0


def exists(
    project_id: str,
    commit_sha: str,
    *,
    driver: Optional[neo4j.Driver] = None,
) -> bool:
    drv = driver or db_provider.connect()
    with drv.session() as session:
        result = session.execute_read(
            lambda tx: tx.run(
                _EXISTS_PROJECT,
                project_id=project_id,
                commit_sha=commit_sha,
            ).single()
        )
    return bool(result["exists"]) if result else False


def node_count(
    project_id: str,
    commit_sha: str,
    *,
    driver: Optional[neo4j.Driver] = None,
) -> int:
    drv = driver or db_provider.connect()
    with drv.session() as session:
        result = session.execute_read(
            lambda tx: tx.run(
                _COUNT_PROJECT,
                project_id=project_id,
                commit_sha=commit_sha,
            ).single()
        )
    return int(result["node_count"]) if result else 0


def _chunked(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]
