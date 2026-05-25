"""Reachability queries: given a vulnerable function (vf), find affected entries.

All queries are bounded by max_depth to avoid runaway traversal in graphs
with cycles. Default 30 hops covers typical app -> TPL -> stdlib chains.

Typical caller flow:
    1. CVE -> vf_qname           (from CVE cache, not Neo4j)
    2. is_reachable(...)         (fast boolean -- short-circuits)
    3. get_affected_entries(...) (only if verdict is AFFECTED)
    4. explain_path(...)         (only if user passed --explain)
"""
from __future__ import annotations

from typing import Optional

import neo4j

from pyshare.graph import db_provider


_IS_REACHABLE = """
MATCH (v:Function {project_id: $project_id, commit_sha: $commit_sha, qname: $vf_qname})
RETURN EXISTS {
  MATCH (e:EntryPoint {project_id: $project_id, commit_sha: $commit_sha})
  WHERE (e)-[:CALLS*1..%d]->(v)
} AS affected
"""

_AFFECTED_ENTRIES = """
MATCH (e:EntryPoint {project_id: $project_id, commit_sha: $commit_sha})
MATCH (v:Function   {project_id: $project_id, commit_sha: $commit_sha, qname: $vf_qname})
WHERE (e)-[:CALLS*1..%d]->(v)
RETURN e.qname AS entry, e.kind AS kind
ORDER BY entry
"""

# Bulk portfolio query: find affected (project, entry) pairs across
# many projects in one Cypher round-trip.
_PORTFOLIO_AFFECTED = """
UNWIND $projects AS p
MATCH (v:Function {project_id: p.project_id, commit_sha: p.commit_sha,
                    qname: $vf_qname})
MATCH (e:EntryPoint {project_id: p.project_id, commit_sha: p.commit_sha})
WHERE (e)-[:CALLS*1..%d]->(v)
RETURN p.project_id   AS project_id,
       p.commit_sha   AS commit_sha,
       e.qname        AS entry
ORDER BY project_id, entry
"""


def is_reachable(
    project_id: str,
    commit_sha: str,
    vf_qname: str,
    *,
    max_depth: int = 30,
    driver: Optional[neo4j.Driver] = None,
) -> bool:
    """True if any entry point reaches vf within max_depth hops."""
    drv = driver or db_provider.connect()
    with drv.session() as session:
        result = session.execute_read(
            lambda tx: tx.run(
                _IS_REACHABLE % max_depth,
                project_id=project_id,
                commit_sha=commit_sha,
                vf_qname=vf_qname,
            ).single()
        )
    return bool(result["affected"]) if result else False


def get_affected_entries(
    project_id: str,
    commit_sha: str,
    vf_qname: str,
    *,
    max_depth: int = 30,
    driver: Optional[neo4j.Driver] = None,
) -> list[dict[str, str]]:
    """Return list of entry-point qnames that can reach vf.

    Each item: {"entry": qname, "kind": "app"}.
    Empty list means NOT_AFFECTED.
    """
    drv = driver or db_provider.connect()
    with drv.session() as session:
        records = session.execute_read(
            lambda tx: list(tx.run(
                _AFFECTED_ENTRIES % max_depth,
                project_id=project_id,
                commit_sha=commit_sha,
                vf_qname=vf_qname,
            ))
        )
    return [{"entry": r["entry"], "kind": r["kind"]} for r in records]


def find_affected_in_portfolio(
    projects: list[dict[str, str]],
    vf_qname: str,
    *,
    max_depth: int = 30,
    driver: Optional[neo4j.Driver] = None,
) -> list[dict[str, str]]:
    """Bulk reachability check across a portfolio of projects.

    Runs a single Cypher query that UNWINDs over the (project_id,
    commit_sha) pairs and returns one row per affected entry.
    """
    if not projects:
        return []
    drv = driver or db_provider.connect()
    with drv.session() as session:
        records = session.execute_read(
            lambda tx: list(tx.run(
                _PORTFOLIO_AFFECTED % max_depth,
                projects=projects,
                vf_qname=vf_qname,
            ))
        )
    return [
        {
            "project_id": r["project_id"],
            "commit_sha": r["commit_sha"],
            "entry": r["entry"],
        }
        for r in records
    ]
