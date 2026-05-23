"""End-to-end demo: JARVIS JSON -> parser -> Neo4j.

Prerequisites:
    1. Neo4j running locally (see top-of-file comments for docker command)
    2. .env file with NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD set
    3. pyshare installed in editable mode: ``pip install -e .``

Run:
    python scripts/demo_load_graph.py <jarvis.json> <project_id> <commit_sha> <app_pkg1,app_pkg2,...>

Example:
    python scripts/demo_load_graph.py \\
        "E:/2026 WorkSpace/Graph/jarvis_runs/mode3_aw.json" \\
        operation-deploy HEAD server

To start Neo4j via docker (one-time):
    docker run -d --name pyshare-neo4j \\
        -p 7474:7474 -p 7687:7687 \\
        -e NEO4J_AUTH=neo4j/pyshare-dev-pwd \\
        neo4j:5-community

Then set in .env: NEO4J_PASSWORD=pyshare-dev-pwd
"""
from __future__ import annotations

import sys
from pathlib import Path

from pyshare.graph import init_schema, project_graph
from pyshare.pipeline.project_scanner import jarvis_parser


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__)
        return 2

    json_path = Path(sys.argv[1])
    project_id = sys.argv[2]
    commit_sha = sys.argv[3]
    app_pkgs = {p.strip() for p in sys.argv[4].split(",") if p.strip()}

    print(f"Loading: {json_path}")
    print(f"  project_id = {project_id}")
    print(f"  commit_sha = {commit_sha}")
    print(f"  app pkgs   = {sorted(app_pkgs)}\n")

    # Parse + classify + prune
    cg = jarvis_parser.parse_jarvis(json_path, app_pkgs, project_id=project_id)
    cg = jarvis_parser.detect_entries(cg, app_pkgs)
    cg = jarvis_parser.prune(cg)
    print("Parser stats:")
    for k, v in cg.stats().items():
        print(f"  {k:18s} {v}")

    # Init Neo4j schema (idempotent)
    print("\nInitializing schema...")
    init_schema()
    print("  done")

    # If a prior load exists for this (project, commit), clear it
    if project_graph.exists(project_id, commit_sha):
        deleted = project_graph.delete(project_id, commit_sha)
        print(f"\nCleared {deleted} stale nodes from previous load")

    # Write
    print("\nWriting to Neo4j...")
    counts = project_graph.write(cg, project_id=project_id, commit_sha=commit_sha)
    print(f"  nodes_written = {counts['nodes_written']}")
    print(f"  edges_written = {counts['edges_written']}")

    # Verify round-trip
    print("\nVerification:")
    print(f"  exists()      = {project_graph.exists(project_id, commit_sha)}")
    print(f"  node_count()  = {project_graph.node_count(project_id, commit_sha)}")

    print("\nDone. Inspect in Neo4j Browser: http://localhost:7474")
    print("Sample query:")
    print(f"  MATCH (f:Function {{project_id: '{project_id}', commit_sha: '{commit_sha}'}})")
    print( "  RETURN f.kind, count(f) ORDER BY count(f) DESC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
