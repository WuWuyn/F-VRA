import json

from typer.testing import CliRunner

from pyshare_client.commands.reachability import app
from pyshare_core.models import LibrarySummary, Verdict
from pyshare_client.reachability.service import check_transitive_reachability, summary_from_callgraph_report


runner = CliRunner()


def _report(tmp_path, name, edges, public_api_aliases=None):
    path = tmp_path / f"{name}-callgraph-package.json"
    path.write_text(
        json.dumps(
            {
                "mode": "package",
                "root": name,
                "public_api_aliases": public_api_aliases or {},
                "edges_detail": edges,
            }
        ),
        encoding="utf-8-sig",
    )
    return path


def test_summary_from_callgraph_report_expands_public_api_aliases():
    summary = summary_from_callgraph_report(
        {
            "mode": "package",
            "public_api_aliases": {"get": "internal.api"},
            "edges_detail": [
                {
                    "caller": "internal.api",
                    "callee": "beta.api",
                    "callee_type": "external",
                }
            ],
        },
        root="requests",
    )

    assert summary.outer_summary["requests.get"] == {"beta.api"}
    assert summary.inner_summary["requests.get"] == {"internal.api"}
    assert summary.api_aliases["requests.get"] == "internal.api"


def test_summary_from_callgraph_report_deroots_src_package_aliases():
    summary = summary_from_callgraph_report(
        {
            "mode": "package",
            "public_api_aliases": {"src.flask.render_template": "src.flask.templating.render_template"},
            "edges_detail": [
                {
                    "caller": "src.flask.templating.render_template",
                    "callee": "src.flask.templating._render",
                    "callee_type": "internal",
                }
            ],
        },
        root="flask",
    )

    assert summary.api_aliases["flask.render_template"] == "src.flask.templating.render_template"
    assert "src.flask.templating.render_template" in summary.inner_summary["flask.render_template"]
    assert summary.inner_paths["flask.render_template"]["src.flask.templating.render_template"] == [
        "flask.render_template",
        "src.flask.templating.render_template",
    ]


def test_summary_from_callgraph_report_preserves_internal_witness_path():
    summary = summary_from_callgraph_report(
        {
            "mode": "package",
            "edges_detail": [
                {"caller": "pkg.api", "callee": "pkg.layer", "callee_type": "internal"},
                {"caller": "pkg.layer", "callee": "pkg.sink", "callee_type": "internal"},
            ],
        },
        root="pkg",
    )

    assert summary.inner_summary["pkg.api"] == {"pkg.layer", "pkg.sink"}
    assert summary.inner_paths["pkg.api"]["pkg.sink"] == ["pkg.api", "pkg.layer", "pkg.sink"]


def test_query_engine_bridges_direct_vulnerable_public_alias():
    summary = LibrarySummary(
        inner_summary={
            "flask.render_template": {"src.flask.templating.render_template"},
            "src.flask.templating.render_template": {"src.flask.templating._render"},
        },
        api_aliases={"flask.render_template": "src.flask.templating.render_template"},
    )
    from pyshare_core.models import EntryPointType, ExternalNode
    from pyshare_client.reachability.engine import ReachabilityQueryEngine

    report = ReachabilityQueryEngine(
        [
            ExternalNode(
                file_path="<external:flask>",
                function_name="flask.render_template",
                qualified_name="flask.render_template",
                entry_type=EntryPointType.UNKNOWN,
                target_module="flask",
                target_name="render_template",
            )
        ],
        {"flask": summary},
        {"flask.render_template"},
    ).check_reachability()

    assert [path.tpl_chain for path in report.paths] == [
        ["flask.render_template", "src.flask.templating.render_template"]
    ]
    assert report.paths[0].vulnerable_target == "flask.render_template"
    assert report.paths[0].used_summaries == ["flask"]


def test_query_engine_uses_summary_witness_path_for_internal_target():
    summary = LibrarySummary(
        inner_summary={"flask.render_template": {"src.flask.templating._render"}},
        inner_paths={
            "flask.render_template": {
                "src.flask.templating._render": [
                    "flask.render_template",
                    "src.flask.templating.render_template",
                    "src.flask.templating._render",
                ],
            },
        },
    )
    from pyshare_core.models import EntryPointType, ExternalNode
    from pyshare_client.reachability.engine import ReachabilityQueryEngine

    report = ReachabilityQueryEngine(
        [
            ExternalNode(
                file_path="<external:flask>",
                function_name="flask.render_template",
                qualified_name="flask.render_template",
                entry_type=EntryPointType.UNKNOWN,
                target_module="flask",
                target_name="render_template",
            )
        ],
        {"flask": summary},
        {"src.flask.templating._render"},
    ).check_reachability()

    assert [path.tpl_chain for path in report.paths] == [
        [
            "flask.render_template",
            "src.flask.templating.render_template",
            "src.flask.templating._render",
        ]
    ]


def test_summary_from_callgraph_report_uses_llm_kept_final_edges():
    summary = summary_from_callgraph_report(
        {
            "mode": "package",
            "edges_detail": [],
            "candidate_edges": [
                {
                    "caller": "requests.get",
                    "callee": "requests.internal",
                    "status": "candidate",
                }
            ],
            "llm_kept_edges": [
                {
                    "caller": "requests.get",
                    "callee": "requests.internal",
                    "callee_type": "internal",
                    "edge_type": "llm_candidate",
                }
            ],
            "final_edges_detail": [
                {
                    "caller": "requests.get",
                    "callee": "requests.internal",
                    "callee_type": "internal",
                    "edge_type": "llm_candidate",
                },
                {
                    "caller": "requests.internal",
                    "callee": "beta.api",
                    "callee_type": "external",
                },
            ],
        },
        root="requests",
    )

    assert summary.inner_summary["requests.get"] == {"requests.internal"}
    assert summary.outer_summary["requests.get"] == {"beta.api"}


def test_check_transitive_reachability_crosses_multiple_package_summaries():
    summaries = {
        "requests": LibrarySummary(
            outer_summary={"requests.get": {"beta.api"}},
        ),
        "beta": LibrarySummary(
            outer_summary={"beta.api": {"gamma.run"}},
        ),
        "gamma": LibrarySummary(
            inner_summary={"gamma.run": {"gamma.internal.vulnerable"}},
        ),
    }

    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"gamma.internal.vulnerable"},
        summaries=summaries,
    )

    assert result.verdict == Verdict.REACHABLE
    assert result.hit_set == ["gamma.internal.vulnerable"]
    assert result.loaded_summaries == ["beta", "gamma", "requests"]
    assert result.used_summaries == ["beta", "gamma", "requests"]
    assert [path.tpl_chain for path in result.paths] == [
        ["pkg.lib.Client.fetch", "requests.get", "beta.api", "gamma.run", "gamma.internal.vulnerable"]
    ]
    assert result.paths[0].used_summaries == ["requests", "beta", "gamma"]


def test_check_transitive_reachability_is_potential_when_middle_summary_missing():
    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"gamma.internal.vulnerable"},
        summaries={
            "requests": LibrarySummary(
                outer_summary={"requests.get": {"beta.api"}},
            )
        },
    )

    assert result.verdict == Verdict.POTENTIALLY_REACHABLE
    assert result.unresolved_targets == ["beta.api"]
    assert result.unresolved_target_related == ["beta.api"]


def test_check_transitive_reachability_is_not_reachable_when_summary_closes_frontier():
    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"gamma.internal.vulnerable"},
        summaries={
            "requests": LibrarySummary(
                outer_summary={"requests.get": set()},
            )
        },
    )

    assert result.verdict == Verdict.NOT_REACHABLE
    assert result.paths == []
    assert result.unresolved_targets == []


def test_check_transitive_reachability_ignores_unrelated_unresolved_frontier():
    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"yaml.load"},
        summaries={"yaml": LibrarySummary()},
    )

    assert result.verdict == Verdict.NOT_REACHABLE
    assert result.unresolved_targets == ["requests.get"]
    assert result.unresolved_target_related == []
    assert result.unresolved_unrelated == ["requests.get"]


def test_check_transitive_reachability_is_potential_for_target_package_unresolved_frontier():
    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"requests.post"},
        summaries={},
    )

    assert result.verdict == Verdict.POTENTIALLY_REACHABLE
    assert result.unresolved_targets == ["requests.get"]
    assert result.unresolved_target_related == ["requests.get"]


def test_check_transitive_reachability_is_potential_for_potential_usage_hit(tmp_path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "main.py").write_text(
        "\n".join(
            [
                "def make_model():",
                "    return object()",
                "",
                "def main():",
                "    model = make_model()",
                "    return model.predict([1])",
                "",
                "if __name__ == '__main__':",
                "    main()",
            ]
        ),
        encoding="utf-8",
    )

    result = check_transitive_reachability(project, {"predict"}, summaries={})

    assert result.verdict == Verdict.POTENTIALLY_REACHABLE
    assert result.hit_set == ["predict"]


def test_check_transitive_reachability_is_potential_when_package_summary_has_raw_candidates():
    result = check_transitive_reachability(
        "tests/fixtures/sample_app",
        {"gamma.internal.vulnerable"},
        summaries={
            "requests": LibrarySummary(
                outer_summary={"requests.get": set()},
                analysis_warnings={
                    "candidate_edges": [
                        {
                            "caller": "requests.get",
                            "callee": "beta.api",
                            "status": "candidate",
                        }
                    ]
                },
            )
        },
    )

    assert result.verdict == Verdict.POTENTIALLY_REACHABLE
    assert "package_summaries" in result.analysis_warnings


def test_reachability_check_cli_reports_transitive_json_path(tmp_path):
    requests_report = _report(
        tmp_path,
        "requests",
        [
            {
                "caller": "internal.api",
                "callee": "beta.api",
                "callee_type": "external",
            }
        ],
        public_api_aliases={"get": "internal.api"},
    )
    beta_report = _report(
        tmp_path,
        "beta",
        [
            {
                "caller": "beta.api",
                "callee": "gamma.run",
                "callee_type": "external",
            }
        ],
    )
    gamma_report = _report(
        tmp_path,
        "gamma",
        [
            {
                "caller": "gamma.run",
                "callee": "gamma.internal.vulnerable",
                "callee_type": "internal",
            }
        ],
    )

    result = runner.invoke(
        app,
        [
            "check",
            "--project",
            "tests/fixtures/sample_app",
            "--vf",
            "gamma.internal.vulnerable",
            "--package-report",
            f"requests={requests_report}",
            "--package-report",
            f"beta={beta_report}",
            "--package-report",
            f"gamma={gamma_report}",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["verdict"] == "reachable"
    assert data["paths"][0]["path"] == [
        "pkg.lib.Client.fetch",
        "requests.get",
        "internal.api",
        "beta.api",
        "gamma.run",
        "gamma.internal.vulnerable",
    ]
    assert data["used_summaries"] == ["beta", "gamma", "requests"]
    assert data["paths"][0]["used_summaries"] == ["requests", "beta", "gamma"]
    assert len(data["paths"][0]["path"]) > 2


def test_reachability_check_cli_rejects_invalid_package_report_spec():
    result = runner.invoke(
        app,
        [
            "check",
            "--project",
            "tests/fixtures/sample_app",
            "--vf",
            "gamma.internal.vulnerable",
            "--package-report",
            "not-a-root-path-pair",
        ],
    )

    assert result.exit_code == 1
    assert "ROOT=PATH" in result.stdout
