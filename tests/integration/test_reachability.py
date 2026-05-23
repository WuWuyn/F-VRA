"""Integration tests for graph/reachability.py and graph/path_explainer.py."""
from __future__ import annotations

import pytest

from pyshare.graph import path_explainer, project_graph, reachability


@pytest.fixture
def loaded_project(clean_test_project, driver, tiny_callgraph):
    """Write tiny_callgraph and return (project_id, commit_sha)."""
    project_id, commit_sha = clean_test_project
    project_graph.write(
        tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
        driver=driver,
    )
    return project_id, commit_sha


class TestIsReachable:
    def test_direct_boundary_edge(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        # myapp.main -> aiohttp.web.run_app  (1 hop)
        assert reachability.is_reachable(
            project_id, commit_sha, "aiohttp.web.run_app", driver=driver,
        ) is True

    def test_two_hop_chain(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        # myapp.main -> myapp.helper -> aiohttp.web._handshake (2 hops)
        assert reachability.is_reachable(
            project_id, commit_sha, "aiohttp.web._handshake", driver=driver,
        ) is True

    def test_unreachable_returns_false(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        # json.dumps is in the graph but has no incoming edge from app.
        assert reachability.is_reachable(
            project_id, commit_sha, "json.dumps", driver=driver,
        ) is False

    def test_nonexistent_vf_returns_false(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        assert reachability.is_reachable(
            project_id, commit_sha, "nonexistent.qname.foo", driver=driver,
        ) is False

    def test_depth_bound_excludes_far_targets(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        # _handshake is 2 hops away — max_depth=1 must miss it.
        assert reachability.is_reachable(
            project_id, commit_sha, "aiohttp.web._handshake",
            max_depth=1, driver=driver,
        ) is False


class TestGetAffectedEntries:
    def test_returns_entry_when_affected(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        entries = reachability.get_affected_entries(
            project_id, commit_sha, "aiohttp.web.run_app", driver=driver,
        )
        assert len(entries) == 1
        assert entries[0]["entry"] == "myapp.main"
        assert entries[0]["kind"] == "app"

    def test_returns_empty_when_unreachable(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        entries = reachability.get_affected_entries(
            project_id, commit_sha, "json.dumps", driver=driver,
        )
        assert entries == []


class TestPathExplain:
    def test_shortest_path_direct(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        chain = path_explainer.explain(
            project_id, commit_sha,
            "myapp.main", "aiohttp.web.run_app", driver=driver,
        )
        assert chain is not None
        assert [n["qname"] for n in chain] == [
            "myapp.main", "aiohttp.web.run_app",
        ]

    def test_shortest_path_two_hops(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        chain = path_explainer.explain(
            project_id, commit_sha,
            "myapp.main", "aiohttp.web._handshake", driver=driver,
        )
        assert chain is not None
        assert [n["qname"] for n in chain] == [
            "myapp.main", "myapp.helper", "aiohttp.web._handshake",
        ]

    def test_unreachable_returns_none(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        chain = path_explainer.explain(
            project_id, commit_sha,
            "myapp.main", "json.dumps", driver=driver,
        )
        assert chain is None

    def test_kind_annotations_in_chain(self, loaded_project, driver):
        project_id, commit_sha = loaded_project
        chain = path_explainer.explain(
            project_id, commit_sha,
            "myapp.main", "aiohttp.web._handshake", driver=driver,
        )
        kinds = [n["kind"] for n in chain]
        assert kinds == ["app", "app", "tpl"]


class TestPortfolioQuery:
    """Bulk reachability across multiple projects (paper's enterprise-scale
    contribution — verify single Cypher returns all affected projects)."""

    def test_returns_only_affected_projects(
        self, driver, tiny_callgraph,
    ):
        # Load the same tiny graph under two project IDs.
        project_graph.write(tiny_callgraph,
                            project_id="proj_A", commit_sha="sha",
                            driver=driver)
        project_graph.write(tiny_callgraph,
                            project_id="proj_B", commit_sha="sha",
                            driver=driver)
        try:
            # Both should be affected by aiohttp.web.run_app.
            rows = reachability.find_affected_in_portfolio(
                projects=[
                    {"project_id": "proj_A", "commit_sha": "sha"},
                    {"project_id": "proj_B", "commit_sha": "sha"},
                ],
                vf_qname="aiohttp.web.run_app",
                driver=driver,
            )
            project_ids = sorted({r["project_id"] for r in rows})
            assert project_ids == ["proj_A", "proj_B"]
            for r in rows:
                assert r["entry"] == "myapp.main"
        finally:
            project_graph.delete("proj_A", "sha", driver=driver)
            project_graph.delete("proj_B", "sha", driver=driver)

    def test_unaffected_project_omitted(self, driver, tiny_callgraph):
        project_graph.write(tiny_callgraph,
                            project_id="proj_A", commit_sha="sha",
                            driver=driver)
        try:
            # Query for vf NOT in the graph -- proj_A should be omitted.
            rows = reachability.find_affected_in_portfolio(
                projects=[{"project_id": "proj_A", "commit_sha": "sha"}],
                vf_qname="requests.sessions.Session.request",
                driver=driver,
            )
            assert rows == []
        finally:
            project_graph.delete("proj_A", "sha", driver=driver)

    def test_empty_portfolio_returns_empty(self, driver):
        rows = reachability.find_affected_in_portfolio(
            projects=[], vf_qname="anything", driver=driver,
        )
        assert rows == []

    def test_one_project_affected_one_not(self, driver, tiny_callgraph):
        from pyshare.pipeline.project_scanner.jarvis_parser import (
            CallEdge, CallGraph, FuncKind, FunctionNode,
        )
        # proj_A: has the affecting graph
        project_graph.write(tiny_callgraph,
                            project_id="proj_A", commit_sha="sha",
                            driver=driver)
        # proj_B: a different graph with only stdlib reachable
        unaffected = CallGraph(
            nodes={
                "myapp.main": FunctionNode(qname="myapp.main",
                                            kind=FuncKind.APP,
                                            is_entry=True),
                "json.dumps": FunctionNode(qname="json.dumps",
                                            kind=FuncKind.STDLIB),
            },
            edges=[CallEdge(caller="myapp.main", callee="json.dumps")],
        )
        project_graph.write(unaffected,
                            project_id="proj_B", commit_sha="sha",
                            driver=driver)
        try:
            rows = reachability.find_affected_in_portfolio(
                projects=[
                    {"project_id": "proj_A", "commit_sha": "sha"},
                    {"project_id": "proj_B", "commit_sha": "sha"},
                ],
                vf_qname="aiohttp.web.run_app",
                driver=driver,
            )
            project_ids = {r["project_id"] for r in rows}
            assert project_ids == {"proj_A"}
        finally:
            project_graph.delete("proj_A", "sha", driver=driver)
            project_graph.delete("proj_B", "sha", driver=driver)
