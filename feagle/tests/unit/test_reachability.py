from pyshare_core.models import ExternalNode, LibrarySummary
from pyshare_client.reachability.engine import ReachabilityQueryEngine


def test_reachability_matches_direct_vulnerable_usage():
    ui = [
        ExternalNode(
            file_path="<external:requests>",
            function_name="requests.get",
            qualified_name="requests.get",
            target_module="requests",
            target_name="get",
        )
    ]

    report = ReachabilityQueryEngine(ui, {}, {"requests.get"}).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["requests.get"]


def test_reachability_expands_library_summary_outer_reach():
    ui = [
        ExternalNode(
            file_path="<external:sample>",
            function_name="sample.public_api",
            qualified_name="sample.public_api",
            target_module="sample",
            target_name="public_api",
        )
    ]
    summary = LibrarySummary(
        inner_summary={"sample.public_api": {"sample.Client.fetch"}},
        outer_summary={"sample.public_api": {"requests.get"}},
    )

    report = ReachabilityQueryEngine(ui, {"sample": summary}, {"requests.get"}).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["sample.public_api", "requests.get"]


def test_reachability_matches_real_jinja_direct_target_shape():
    report = ReachabilityQueryEngine(
        [_external("jinja2.utils.urlize")],
        {},
        {"jinja2.utils.urlize"},
    ).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["jinja2.utils.urlize"]


def test_reachability_expands_real_jinja_transitive_dependency_shape():
    summary = LibrarySummary(
        outer_summary={"jinja2.utils.urlize": {"markupsafe.escape", "re.search"}},
    )

    report = ReachabilityQueryEngine(
        [_external("jinja2.utils.urlize")],
        {"jinja2": summary},
        {"markupsafe.escape"},
    ).check_reachability()

    assert report.is_vulnerable is True
    assert report.paths[0].tpl_chain == ["jinja2.utils.urlize", "markupsafe.escape"]


def test_reachability_composes_real_jinja_markupsafe_internal_shape():
    summaries = {
        "jinja2": LibrarySummary(
            outer_summary={"jinja2.utils.urlize": {"markupsafe.escape", "re.search"}},
        ),
        "markupsafe": LibrarySummary(
            inner_summary={"escape": {"_native._escape_inner"}},
        ),
    }

    report = ReachabilityQueryEngine(
        [_external("jinja2.utils.urlize")],
        summaries,
        {"markupsafe._native._escape_inner"},
    ).check_reachability()

    assert report.is_vulnerable is True
    assert report.used_summaries == ["jinja2", "markupsafe"]
    assert report.paths[0].tpl_chain == [
        "jinja2.utils.urlize",
        "markupsafe.escape",
        "markupsafe._native._escape_inner",
    ]
    assert report.paths[0].used_summaries == ["jinja2", "markupsafe"]


def test_reachability_reports_missing_dependency_summary_frontier():
    summary = LibrarySummary(
        outer_summary={"jinja2.utils.urlize": {"markupsafe.escape"}},
    )

    report = ReachabilityQueryEngine(
        [_external("jinja2.utils.urlize")],
        {"jinja2": summary},
        {"markupsafe._native._escape_inner"},
    ).check_reachability()

    assert report.is_vulnerable is False
    assert report.paths == []
    assert report.used_summaries == []
    assert report.unresolved_targets == ["markupsafe.escape"]


def _external(target: str) -> ExternalNode:
    module, _, name = target.rpartition(".")
    return ExternalNode(
        file_path=f"<external:{module}>",
        function_name=target,
        qualified_name=target,
        target_module=module,
        target_name=name,
    )


def test_reachability_composes_multiple_package_summaries():
    summaries = {
        "alpha": LibrarySummary(
            outer_summary={"alpha.start": {"beta.api"}},
        ),
        "beta": LibrarySummary(
            outer_summary={"beta.api": {"gamma.run"}},
        ),
        "gamma": LibrarySummary(
            inner_summary={"gamma.run": {"gamma.internal.vulnerable"}},
        ),
    }

    report = ReachabilityQueryEngine(
        [_external("alpha.start")],
        summaries,
        {"gamma.internal.vulnerable"},
    ).check_reachability()

    assert [path.tpl_chain for path in report.paths] == [
        ["alpha.start", "beta.api", "gamma.run", "gamma.internal.vulnerable"]
    ]


def test_reachability_preserves_converging_transitive_paths():
    summaries = {
        "alpha": LibrarySummary(
            outer_summary={
                "alpha.one": {"beta.api"},
                "alpha.two": {"beta.api"},
            },
        ),
        "beta": LibrarySummary(
            outer_summary={"beta.api": {"sink.execute"}},
        ),
    }

    report = ReachabilityQueryEngine(
        [_external("alpha.one"), _external("alpha.two")],
        summaries,
        {"sink.execute"},
    ).check_reachability()

    assert {tuple(path.tpl_chain) for path in report.paths} == {
        ("alpha.one", "beta.api", "sink.execute"),
        ("alpha.two", "beta.api", "sink.execute"),
    }


def test_reachability_stops_cycles_and_honors_path_limit():
    summaries = {
        "alpha": LibrarySummary(
            outer_summary={"alpha.start": {"beta.api"}},
        ),
        "beta": LibrarySummary(
            outer_summary={"beta.api": {"alpha.start", "sink.one", "sink.two"}},
        ),
    }

    report = ReachabilityQueryEngine(
        [_external("alpha.start")],
        summaries,
        {"sink.one", "sink.two"},
        max_paths=1,
    ).check_reachability()

    assert report.is_vulnerable is True
    assert len(report.paths) == 1
    assert report.paths[0].tpl_chain[0:2] == ["alpha.start", "beta.api"]


def test_reachability_suffix_matches_inner_summary_target():
    summary = LibrarySummary(
        inner_summary={"sample.public_api": {"sample.deep.Client.fetch"}},
    )

    report = ReachabilityQueryEngine(
        [_external("sample.public_api")],
        {"sample": summary},
        {"Client.fetch"},
    ).check_reachability()

    assert report.paths[0].tpl_chain == ["sample.public_api", "sample.deep.Client.fetch"]


def test_reachability_reports_frontier_without_package_summary():
    report = ReachabilityQueryEngine(
        [_external("sample.public_api")],
        {},
        {"sample.internal.vulnerable"},
    ).check_reachability()

    assert report.is_vulnerable is False
    assert report.unresolved_targets == ["sample.public_api"]
