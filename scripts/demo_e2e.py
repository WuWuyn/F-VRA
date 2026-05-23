"""End-to-end demo: parse JARVIS JSON -> Neo4j -> reachability query.

Run with no args for the canned operation-deploy demo.

This script intentionally tests several vf candidates against the
operation-deploy/server.py call graph to demonstrate both verdicts:

    Reachable (AFFECTED):
        aiohttp.web_ws.WebSocketResponse.prepare  -- direct call from ws_handler
        aiohttp.web_ws.WebSocketResponse.send_str -- via Player.send
        aiohttp.web.run_app                       -- via main

    Not reachable (NOT_AFFECTED):
        requests.sessions.Session.request         -- not in graph (server doesn't use requests)
"""
from __future__ import annotations

from pathlib import Path

from pyshare.graph import init_schema, path_explainer, project_graph, reachability
from pyshare.pipeline.project_scanner import jarvis_parser


JARVIS_JSON = Path(r"E:\2026 WorkSpace\Graph\jarvis_runs\mode3_aw.json")
PROJECT_ID = "operation-deploy"
COMMIT_SHA = "HEAD"
APP_PKGS = {"server"}

VF_CANDIDATES = [
    ("aiohttp.web_ws.WebSocketResponse.prepare", "direct boundary edge"),
    ("aiohttp.web_ws.WebSocketResponse.send_str", "via Player.send"),
    ("aiohttp.web.run_app", "via main"),
    ("base64.b64decode", "deep transitive (via prepare -> _pre_start -> _handshake)"),
    ("requests.sessions.Session.request", "NOT in graph — should be NOT_AFFECTED"),
]


def banner(s: str) -> None:
    print(f"\n{'=' * 60}\n{s}\n{'=' * 60}")


def main() -> None:
    banner("STEP 1 — Parse + prune JARVIS output")
    cg = jarvis_parser.parse_jarvis(JARVIS_JSON, APP_PKGS, project_id=PROJECT_ID)
    cg = jarvis_parser.detect_entries(cg, APP_PKGS)
    cg = jarvis_parser.prune(cg)
    print(f"  nodes:   {len(cg.nodes)}")
    print(f"  edges:   {len(cg.edges)}")
    print(f"  entries: {sum(1 for n in cg.nodes.values() if n.is_entry)}")

    banner("STEP 2 — Init Neo4j schema (idempotent)")
    init_schema()
    print("  done")

    banner("STEP 3 — Write to Neo4j")
    if project_graph.exists(PROJECT_ID, COMMIT_SHA):
        n = project_graph.delete(PROJECT_ID, COMMIT_SHA)
        print(f"  cleared {n} stale nodes")
    counts = project_graph.write(cg, project_id=PROJECT_ID, commit_sha=COMMIT_SHA)
    print(f"  nodes written: {counts['nodes_written']}")
    print(f"  edges written: {counts['edges_written']}")
    print(f"  verify:        node_count() = {project_graph.node_count(PROJECT_ID, COMMIT_SHA)}")

    banner("STEP 4 — Reachability checks for candidate vfs")
    for vf, note in VF_CANDIDATES:
        affected = reachability.is_reachable(PROJECT_ID, COMMIT_SHA, vf)
        verdict = "AFFECTED" if affected else "NOT_AFFECTED"
        print(f"\n  vf = {vf}")
        print(f"  ({note})")
        print(f"  verdict: {verdict}")
        if affected:
            entries = reachability.get_affected_entries(PROJECT_ID, COMMIT_SHA, vf)
            print(f"  via entries:")
            for e in entries:
                print(f"    - {e['entry']}")
            # Explain via first entry
            if entries:
                chain = path_explainer.explain(
                    PROJECT_ID, COMMIT_SHA, entries[0]["entry"], vf,
                )
                if chain:
                    print(f"  shortest chain ({len(chain)} hops):")
                    for n in chain:
                        print(f"    [{n['kind']:6s}] {n['qname']}")

    banner("DONE")
    print("Inspect in Neo4j Browser: http://localhost:7474")


if __name__ == "__main__":
    main()
