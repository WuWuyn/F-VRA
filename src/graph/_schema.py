"""Neo4j schema setup for PyShare project graphs.

Schema (project-level, JARVIS-sourced):

    (:Function {
        project_id:  STRING,
        commit_sha:  STRING,
        qname:       STRING,
        kind:        STRING,    # app | tpl | stdlib | builtin | type_method | unresolved
        is_entry:    BOOLEAN,
    })

    # Dual label: nodes with is_entry=true also carry :EntryPoint
    (:EntryPoint:Function {...})

    -[:CALLS {source: STRING}]->

Identity is (project_id, commit_sha, qname). Multiple commits of the same
project coexist; multiple projects coexist; the same qname (e.g. an
aiohttp function) appears once per (project, commit) tuple.

Reachability queries should start from :EntryPoint (faster than
filtering on is_entry property):

    MATCH (e:EntryPoint {project_id: $p, commit_sha: $c})
    MATCH (v:Function   {project_id: $p, commit_sha: $c, qname: $vf})
    RETURN EXISTS { (e)-[:CALLS*1..30]->(v) } AS affected
"""
from __future__ import annotations

from typing import Optional

import neo4j

from pyshare.graph import db_provider


SCHEMA_STATEMENTS: list[str] = [
    """
    CREATE CONSTRAINT func_unique IF NOT EXISTS
    FOR (f:Function)
    REQUIRE (f.project_id, f.commit_sha, f.qname) IS UNIQUE
    """,
    """
    CREATE INDEX func_qname IF NOT EXISTS
    FOR (f:Function) ON (f.qname)
    """,
    """
    CREATE INDEX func_project IF NOT EXISTS
    FOR (f:Function) ON (f.project_id, f.commit_sha)
    """,
    """
    CREATE INDEX func_kind IF NOT EXISTS
    FOR (f:Function) ON (f.kind)
    """,
]


def init_schema(driver: Optional[neo4j.Driver] = None) -> None:
    """Create constraints and indexes. Safe to call repeatedly."""
    drv = driver or db_provider.connect()
    with drv.session() as session:
        for stmt in SCHEMA_STATEMENTS:
            session.run(stmt)
