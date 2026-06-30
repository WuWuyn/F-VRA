from pyshare_core.models import Verdict
from pyshare_client.reachability.service import query


def test_query_builds_project_usage_and_reports_direct_reachability():
    result = query(
        cve_id="CVE-TEST",
        project="tests/fixtures/sample_app",
        vf="requests.get",
        explain=True,
    )

    assert result.verdict == Verdict.REACHABLE
    assert result.hit_set == ["requests.get"]
    assert result.call_chain == ["pkg.lib.Client.fetch", "requests.get"]
    assert result.entry_points


def test_query_without_vulnerable_target_is_unknown():
    result = query(
        cve_id="CVE-TEST",
        project="tests/fixtures/sample_app",
        vf="",
    )

    assert result.verdict == Verdict.UNKNOWN


def test_query_is_potential_when_dependency_summary_is_missing():
    result = query(
        cve_id="CVE-TEST",
        project="tests/fixtures/sample_app",
        vf="requests.sessions.Session.request",
    )

    assert result.verdict == Verdict.POTENTIALLY_REACHABLE
