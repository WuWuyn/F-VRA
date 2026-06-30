from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pyshare_api.db.models import (
    Advisory,
    AdvisoryAffectedPackage,
    AdvisoryAlias,
    Artifact,
    Base,
    Dependency,
    Project,
    ProjectRevision,
    ReachabilityPathRow,
    ScanFinding,
    ScanJob,
    VulnerableEntity,
)
from pyshare_api.db.repository import FvraRepository
from pyshare_api.routes.jobs import cli_scan_plan
from pyshare_api.schemas import CliDependency, CliScanPlanRequest


def make_repo():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = Session()
    return FvraRepository(session), session


def seed_advisory(session):
    advisory = Advisory(canonical_id="CVE-TEST-REQUESTS", title="requests test", description="requests.get is vulnerable")
    session.add(advisory)
    session.flush()
    affected = AdvisoryAffectedPackage(
        advisory_id=advisory.id,
        ecosystem="pypi",
        package_name="requests",
        normalized_name="requests",
        affected_versions=["==2.31.0"],
        fixed_versions=["2.32.0"],
    )
    session.add(affected)
    session.flush()
    session.add(AdvisoryAlias(advisory_id=advisory.id, alias="GHSA-TEST", alias_type="GHSA"))
    session.add(VulnerableEntity(advisory_id=advisory.id, affected_package_id=affected.id, package_name="requests", name="requests.get", confidence=1.0))
    session.commit()


def test_advisory_alias_and_affected_version_match():
    repo, session = make_repo()
    seed_advisory(session)
    project = repo.create_project(name="sample", repo_url="file:///sample", branch="main")
    revision = repo.upsert_project_revision(project_id=project.id, branch="main", commit_sha="abc", dependency_fingerprint="deps")
    repo.replace_dependencies(revision.id, [{"package_name": "requests", "normalized_name": "requests", "version": "2.31.0", "ecosystem": "pypi"}])

    matches = repo.matching_vulnerabilities(revision.id, ["GHSA-TEST"])

    assert len(matches) == 1
    advisory, affected, dependency, entities = matches[0]
    assert advisory.canonical_id == "CVE-TEST-REQUESTS"
    assert affected.fixed_versions == ["2.32.0"]
    assert dependency.package_name == "requests"
    assert [entity.name for entity in entities] == ["requests.get"]


def test_project_name_must_be_unique_case_insensitive():
    repo, _session = make_repo()
    repo.create_project(name="Candyfloss Flask", repo_url="file:///sample", branch="main")

    try:
        repo.create_project(name=" candyfloss flask ", repo_url="file:///other", branch="main")
    except ValueError as exc:
        assert str(exc) == "Project name already exists."
    else:
        raise AssertionError("Expected duplicate project name to be rejected")


def test_artifact_reuse_by_stable_key(tmp_path):
    repo, session = make_repo()

    first = repo.upsert_artifact(kind="package-summary", reusable_key="pypi:requests:2.31.0", payload={"a": 1}, storage_root=tmp_path)
    second = repo.upsert_artifact(kind="package-summary", reusable_key="pypi:requests:2.31.0", payload={"a": 1}, storage_root=tmp_path)

    assert first.id == second.id
    assert session.query(Artifact).count() == 1


def test_scan_job_status_transitions():
    repo, session = make_repo()
    project = repo.create_project(name="sample", repo_url="file:///sample", branch="main")
    queued = repo.create_scan_job(project.id)

    claimed = repo.claim_next_scan_job()
    assert claimed is not None
    assert claimed.id == queued.id
    assert claimed.status == "running"

    repo.mark_scan_completed(claimed)
    assert session.get(ScanJob, queued.id).status == "completed"


def test_delete_project_removes_scan_and_revision_rows():
    repo, session = make_repo()
    project = repo.create_project(name="sample", repo_url="file:///sample", branch="main")
    revision = repo.upsert_project_revision(project_id=project.id, branch="main", commit_sha="abc", dependency_fingerprint="deps")
    repo.replace_dependencies(revision.id, [{"package_name": "requests", "normalized_name": "requests", "version": "2.31.0", "ecosystem": "pypi"}])
    scan = repo.create_scan_job(project.id)
    finding = repo.add_scan_finding(
        scan_id=scan.id,
        advisory_id="CVE-TEST",
        package_name="requests",
        package_version="2.31.0",
        vulnerable_function="requests.get",
        verdict="reachable",
        severity="High",
        summary="test",
        fixed_version="2.32.0",
        score=8.0,
        paths=[{"project_api": "app.main", "target": "requests.get", "path": ["app.main", "requests.get"], "used_summaries": []}],
    )

    assert repo.delete_project(project.id) is True

    assert session.get(Project, project.id) is None
    assert session.get(ProjectRevision, revision.id) is None
    assert session.query(Dependency).count() == 0
    assert session.get(ScanJob, scan.id) is None
    assert session.get(ScanFinding, finding.id) is None
    assert session.query(ReachabilityPathRow).count() == 0
    assert repo.delete_project(project.id) is False


def test_dashboard_counts_latest_completed_scan_only():
    repo, session = make_repo()
    project = repo.create_project(name="sample", repo_url="file:///sample", branch="main")
    revision = repo.upsert_project_revision(project_id=project.id, branch="main", commit_sha="abc", dependency_fingerprint="deps")
    repo.replace_dependencies(revision.id, [{"package_name": "requests", "normalized_name": "requests", "version": "2.31.0", "ecosystem": "pypi", "direct": True}])
    first = repo.create_scan_job(project.id)
    repo.add_scan_finding(
        scan_id=first.id,
        advisory_id="CVE-OLD",
        package_name="requests",
        package_version="2.31.0",
        vulnerable_function="requests.old",
        verdict="reachable",
        severity="High",
        summary="old",
        fixed_version="2.32.0",
        score=8.0,
        paths=[],
    )
    repo.mark_scan_completed(first)
    second = repo.create_scan_job(project.id)
    repo.mark_scan_completed(second)

    summary = repo.dashboard_summary()

    assert summary.projects[0].vulnerabilities == 0
    assert summary.projects[0].reachable == 0
    assert summary.projects[0].dependencies == 1
    assert summary.projects[0].directDependencies == 1
    assert summary.findings == []
    assert summary.packages[0].vulnerabilities == 0


def test_dashboard_findings_use_project_name_with_project_id_for_routing():
    repo, session = make_repo()
    project = repo.create_project(name="Candyfloss Flask", repo_url="file:///sample", branch="main")
    repo.upsert_project_revision(project_id=project.id, branch="main", commit_sha="abc", dependency_fingerprint="deps")
    scan = repo.create_scan_job(project.id)
    repo.add_scan_finding(
        scan_id=scan.id,
        advisory_id="CVE-TEST",
        package_name="flask",
        package_version="2.3.2",
        vulnerable_function="flask.render_template",
        verdict="reachable",
        severity="High",
        summary="test",
        fixed_version="2.3.3",
        score=7.4,
        paths=[],
    )
    repo.mark_scan_completed(scan)

    summary = repo.dashboard_summary()

    assert summary.findings[0].project == "Candyfloss Flask"
    assert summary.findings[0].projectId == project.id
    assert summary.scans[0].project == "Candyfloss Flask"
    assert summary.scans[0].projectId == project.id


def test_cli_scan_plan_matches_server_advisory_and_returns_relevant_summary(tmp_path):
    repo, session = make_repo()
    advisory = Advisory(canonical_id="CVE-CLI-TRANSITIVE", title="urllib3 test", description="urllib3 target")
    session.add(advisory)
    session.flush()
    affected = AdvisoryAffectedPackage(
        advisory_id=advisory.id,
        ecosystem="pypi",
        package_name="urllib3",
        normalized_name="urllib3",
        affected_versions=["==2.7.0"],
        fixed_versions=["2.7.1"],
    )
    session.add(affected)
    session.flush()
    session.add(
        VulnerableEntity(
            advisory_id=advisory.id,
            affected_package_id=affected.id,
            package_name="urllib3",
            name="urllib3.connectionpool.HTTPConnectionPool.urlopen",
            confidence=1.0,
        )
    )
    repo.upsert_artifact(
        kind="package-summary",
        reusable_key="pypi:requests:2.34.2:py3.12:0.3.0",
        payload={"summary": {"outer_summary": {"requests.get": ["urllib3.connectionpool.HTTPConnectionPool.urlopen"]}}},
        storage_root=tmp_path,
        metadata={"package": "requests", "version": "2.34.2"},
    )
    session.commit()

    response = cli_scan_plan(
        CliScanPlanRequest(
            cveIds=["CVE-CLI-TRANSITIVE"],
            usageRoots=["requests"],
            dependencies=[
                CliDependency(name="requests", normalizedName="requests", version="2.34.2", direct=True, dependencies=["urllib3<3"]),
                CliDependency(name="urllib3", normalizedName="urllib3", version="2.7.0", direct=False),
            ],
        ),
        session,
    )

    assert [match.advisoryId for match in response.matches] == ["CVE-CLI-TRANSITIVE"]
    assert response.matches[0].package == "urllib3"
    assert response.matches[0].vulnerableFunctions == ["urllib3.connectionpool.HTTPConnectionPool.urlopen"]
    assert [summary.root for summary in response.packageSummaries] == ["requests"]
