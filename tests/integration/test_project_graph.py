"""Integration tests for graph/project_graph.py against live Neo4j."""
from __future__ import annotations

import pytest

from pyshare.graph import project_graph


class TestWriteAndExists:
    def test_initially_does_not_exist(self, clean_test_project, driver):
        project_id, commit_sha = clean_test_project
        assert project_graph.exists(project_id, commit_sha, driver=driver) is False

    def test_write_then_exists(self, clean_test_project, driver, tiny_callgraph):
        project_id, commit_sha = clean_test_project
        result = project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        assert result["nodes_written"] == 5
        assert result["edges_written"] == 3
        assert project_graph.exists(project_id, commit_sha, driver=driver) is True

    def test_node_count_matches(self, clean_test_project, driver, tiny_callgraph):
        project_id, commit_sha = clean_test_project
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        assert project_graph.node_count(project_id, commit_sha, driver=driver) == 5


class TestEntryPointDualLabel:
    def test_entry_node_has_entrypoint_label(
        self, clean_test_project, driver, tiny_callgraph,
    ):
        project_id, commit_sha = clean_test_project
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        with driver.session() as s:
            r = s.run(
                "MATCH (e:EntryPoint {project_id:$p, commit_sha:$c}) "
                "RETURN e.qname AS qn ORDER BY qn",
                p=project_id, c=commit_sha,
            ).data()
        assert [row["qn"] for row in r] == ["myapp.main"]

    def test_non_entry_does_not_have_entrypoint_label(
        self, clean_test_project, driver, tiny_callgraph,
    ):
        project_id, commit_sha = clean_test_project
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        with driver.session() as s:
            r = s.run(
                "MATCH (f:Function {qname:'myapp.helper'}) "
                "RETURN labels(f) AS labels"
            ).single()
        assert "EntryPoint" not in r["labels"]


class TestDelete:
    def test_delete_removes_all_nodes(
        self, clean_test_project, driver, tiny_callgraph,
    ):
        project_id, commit_sha = clean_test_project
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        n = project_graph.delete(project_id, commit_sha, driver=driver)
        assert n == 5
        assert project_graph.exists(project_id, commit_sha, driver=driver) is False
        assert project_graph.node_count(project_id, commit_sha, driver=driver) == 0

    def test_delete_only_affects_this_project(
        self, clean_test_project, driver, tiny_callgraph,
    ):
        project_id, commit_sha = clean_test_project
        # Write to two different (project, commit) tuples.
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha="other_sha",
            driver=driver,
        )
        try:
            n = project_graph.delete(project_id, commit_sha, driver=driver)
            assert n == 5
            # Other commit still intact.
            assert project_graph.node_count(
                project_id, "other_sha", driver=driver
            ) == 5
        finally:
            project_graph.delete(project_id, "other_sha", driver=driver)


class TestMergeSemantics:
    def test_double_write_is_idempotent(
        self, clean_test_project, driver, tiny_callgraph,
    ):
        project_id, commit_sha = clean_test_project
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        # Second write must not duplicate.
        project_graph.write(
            tiny_callgraph, project_id=project_id, commit_sha=commit_sha,
            driver=driver,
        )
        assert project_graph.node_count(project_id, commit_sha, driver=driver) == 5
        with driver.session() as s:
            r = s.run(
                "MATCH (a:Function {project_id:$p, commit_sha:$c})"
                "-[r:CALLS]->(b:Function {project_id:$p, commit_sha:$c}) "
                "RETURN count(r) AS n",
                p=project_id, c=commit_sha,
            ).single()
        assert r["n"] == 3
