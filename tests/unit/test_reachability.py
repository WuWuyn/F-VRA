from pyshare.core.models import ExternalNode, LibrarySummary
from pyshare.reachability.engine import ReachabilityQueryEngine


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
