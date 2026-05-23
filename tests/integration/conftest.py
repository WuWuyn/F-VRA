"""Integration test fixtures — require a live Neo4j on bolt://localhost:7687.

Skips the whole module if Neo4j is unreachable, so the test suite still
passes on machines without Docker. To run these locally:

    docker run -d --name pyshare-neo4j \\
        -p 7474:7474 -p 7687:7687 \\
        -e NEO4J_AUTH=neo4j/pyshare-dev-pwd \\
        neo4j:5-community
    pytest tests/integration/
"""
from __future__ import annotations

import pytest

from pyshare.core.config import settings
from pyshare.pipeline.project_scanner.jarvis_parser import (
    CallEdge,
    CallGraph,
    FuncKind,
    FunctionNode,
)


def _neo4j_available() -> bool:
    try:
        import neo4j
        drv = neo4j.GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        try:
            drv.verify_connectivity()
            return True
        finally:
            drv.close()
    except Exception:
        return False


# Module-level skip: every test in tests/integration/ requires Neo4j.
pytestmark = pytest.mark.skipif(
    not _neo4j_available(),
    reason=f"Neo4j not reachable at {settings.neo4j_uri}",
)


@pytest.fixture(scope="session")
def driver():
    """Shared Neo4j driver. Schema is initialized once at session start."""
    import neo4j
    from pyshare.graph import init_schema

    drv = neo4j.GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    init_schema(driver=drv)
    yield drv
    drv.close()


@pytest.fixture
def clean_test_project(driver):
    """Yields a (project_id, commit_sha) pair guaranteed empty in the DB.

    Cleans up any nodes for this identity both before yield (to recover
    from earlier failed runs) and after (so the next test starts fresh).
    """
    from pyshare.graph import project_graph

    project_id = "_pytest_proj"
    commit_sha = "_pytest_sha"
    # Pre-clean
    project_graph.delete(project_id, commit_sha, driver=driver)
    yield (project_id, commit_sha)
    # Post-clean
    project_graph.delete(project_id, commit_sha, driver=driver)


@pytest.fixture
def tiny_callgraph() -> CallGraph:
    """A minimal fixture graph covering app/tpl/stdlib + an entry +
    a reachable vf 2 hops away."""
    nodes = {
        # App layer
        "myapp.main": FunctionNode(
            qname="myapp.main", kind=FuncKind.APP, is_entry=True,
        ),
        "myapp.helper": FunctionNode(
            qname="myapp.helper", kind=FuncKind.APP, is_entry=False,
        ),
        # TPL boundary
        "aiohttp.web.run_app": FunctionNode(
            qname="aiohttp.web.run_app", kind=FuncKind.TPL,
        ),
        # Deeper TPL — reachable via helper
        "aiohttp.web._handshake": FunctionNode(
            qname="aiohttp.web._handshake", kind=FuncKind.TPL,
        ),
        # Stdlib — unreachable from app
        "json.dumps": FunctionNode(
            qname="json.dumps", kind=FuncKind.STDLIB,
        ),
    }
    edges = [
        CallEdge(caller="myapp.main", callee="aiohttp.web.run_app"),
        CallEdge(caller="myapp.main", callee="myapp.helper"),
        CallEdge(caller="myapp.helper", callee="aiohttp.web._handshake"),
        # NOTE: json.dumps is orphan — not reachable from myapp.main
    ]
    return CallGraph(nodes=nodes, edges=edges, project_id="_pytest_proj")
