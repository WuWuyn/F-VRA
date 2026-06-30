from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pyshare_api.db.models import Advisory, AdvisoryAffectedPackage, Base, ScanFinding, VulnerableEntity
from pyshare_api.db.repository import FvraRepository
import pyshare_api.worker as worker
from pyshare_core.models import AnalysisFingerprint, DependencyGraphArtifact, DependencyRecord, ProjectIdentity


def run(args: list[str], cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def make_session(tmp_path: Path):
    engine = create_engine(f"sqlite:///{tmp_path / 'pipeline.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return Session


def seed_requests_advisory(session) -> None:
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
    session.add(VulnerableEntity(advisory_id=advisory.id, affected_package_id=affected.id, package_name="requests", name="requests.get", confidence=1.0))
    session.commit()


def seed_gamma_advisory(session) -> None:
    advisory = Advisory(canonical_id="CVE-TEST-GAMMA", title="gamma test", description="gamma.internal.vulnerable is vulnerable")
    session.add(advisory)
    session.flush()
    affected = AdvisoryAffectedPackage(
        advisory_id=advisory.id,
        ecosystem="pypi",
        package_name="gamma",
        normalized_name="gamma",
        affected_versions=["==3.0.0"],
        fixed_versions=["3.0.1"],
    )
    session.add(affected)
    session.flush()
    session.add(
        VulnerableEntity(
            advisory_id=advisory.id,
            affected_package_id=affected.id,
            package_name="gamma",
            name="gamma.internal.vulnerable",
            confidence=1.0,
        )
    )
    session.commit()


def make_git_project(tmp_path: Path) -> Path:
    source = Path("tests/fixtures/sample_app").resolve()
    repo = tmp_path / "sample_repo"
    shutil.copytree(source, repo)
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    run(["git", "init"], cwd=repo)
    run(["git", "add", "."], cwd=repo)
    run(["git", "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "fixture"], cwd=repo)
    return repo


def dependency_graph(project_path: Path) -> DependencyGraphArtifact:
    return DependencyGraphArtifact(
        project=ProjectIdentity(root=str(project_path), fingerprint="transitive-deps"),
        fingerprint=AnalysisFingerprint(scanner_version="0.3.0", python_version="test"),
        source_files=[str(project_path / "requirements.txt")],
        dependencies=[
            DependencyRecord(name="requests", normalized_name="requests", version="2.31.0", direct=True, dependencies=["beta"]),
            DependencyRecord(name="beta", normalized_name="beta", version="2.0.0", direct=False, dependencies=["gamma"]),
            DependencyRecord(name="gamma", normalized_name="gamma", version="3.0.0", direct=False, dependencies=[]),
        ],
    )


def seed_summary_artifact(repo: FvraRepository, tmp_path: Path, dependency: DependencyRecord, summary: dict) -> None:
    repo.upsert_artifact(
        kind="package-summary",
        reusable_key=worker._dependency_summary_key(dependency),
        payload={
            "package": dependency.name,
            "version": dependency.version,
            "summary": {
                "inner_summary": summary.get("inner_summary", {}),
                "outer_summary": summary.get("outer_summary", {}),
                "inner_paths": summary.get("inner_paths", {}),
                "outer_paths": summary.get("outer_paths", {}),
                "analysis_warnings": {},
                "api_aliases": {},
            },
        },
        storage_root=tmp_path / "artifacts",
        node_count=1,
        edge_count=1,
    )


def test_worker_pipeline_queries_db_and_persists_reachability(tmp_path, monkeypatch):
    Session = make_session(tmp_path)
    monkeypatch.setattr(worker, "SessionLocal", Session)
    monkeypatch.setattr(worker, "create_schema", lambda: None)
    monkeypatch.setenv("F_VRA_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("F_VRA_CHECKOUT_ROOT", str(tmp_path / "checkouts"))

    with Session() as session:
        seed_requests_advisory(session)
        repo = FvraRepository(session)
        git_repo = make_git_project(tmp_path)
        project = repo.create_project(name="sample", repo_url=str(git_repo), branch="master")
        job = repo.create_scan_job(project.id)

    assert worker.process_one() is True

    with Session() as session:
        repo = FvraRepository(session)
        completed = repo.get_scan_job(job.id)
        assert completed is not None
        assert completed.status == "completed"
        findings = session.query(ScanFinding).all()
        assert len(findings) == 1
        assert findings[0].advisory_id == "CVE-TEST-REQUESTS"
        assert findings[0].vulnerable_function == "requests.get"
        assert findings[0].verdict == "reachable"
        assert findings[0].paths[0].path == [
            "pkg.app.main",
            "pkg.lib.public_api",
            "pkg.lib.Client.fetch",
            "requests.get",
            "requests.api.get",
        ]
        assert findings[0].paths[0].project_api == "pkg.lib.Client.fetch"
        assert findings[0].paths[0].nodes[0]["file"]
        assert "requests.get" in findings[0].paths[0].nodes[2]["sourceSnippet"]
        summary = repo.dashboard_summary()
        assert summary.projects[0].dependencies >= 1
        assert summary.findings[0].id == "CVE-TEST-REQUESTS"
        assert (tmp_path / "artifacts").exists()


def test_worker_pipeline_reaches_vulnerability_in_transitive_dependency(tmp_path, monkeypatch):
    Session = make_session(tmp_path)
    monkeypatch.setattr(worker, "SessionLocal", Session)
    monkeypatch.setattr(worker, "create_schema", lambda: None)
    monkeypatch.setattr(worker, "resolve_dependency_graph", dependency_graph)
    monkeypatch.setenv("F_VRA_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("F_VRA_CHECKOUT_ROOT", str(tmp_path / "checkouts"))

    deps = dependency_graph(tmp_path).dependencies
    with Session() as session:
        seed_gamma_advisory(session)
        repo = FvraRepository(session)
        seed_summary_artifact(
            repo,
            tmp_path,
            deps[0],
            {
                "outer_summary": {"requests.get": ["beta.api"]},
                "outer_paths": {"requests.get": {"beta.api": ["requests.get", "beta.api"]}},
            },
        )
        seed_summary_artifact(
            repo,
            tmp_path,
            deps[1],
            {
                "outer_summary": {"beta.api": ["gamma.run"]},
                "outer_paths": {"beta.api": {"gamma.run": ["beta.api", "gamma.run"]}},
            },
        )
        seed_summary_artifact(
            repo,
            tmp_path,
            deps[2],
            {
                "inner_summary": {"gamma.run": ["gamma.internal.vulnerable"]},
                "inner_paths": {"gamma.run": {"gamma.internal.vulnerable": ["gamma.run", "gamma.internal.vulnerable"]}},
            },
        )
        git_repo = make_git_project(tmp_path)
        project = repo.create_project(name="sample-transitive", repo_url=str(git_repo), branch="master")
        job = repo.create_scan_job(project.id)

    assert worker.process_one() is True

    with Session() as session:
        repo = FvraRepository(session)
        completed = repo.get_scan_job(job.id)
        assert completed is not None
        assert completed.status == "completed"
        findings = session.query(ScanFinding).all()
        assert len(findings) == 1
        assert findings[0].advisory_id == "CVE-TEST-GAMMA"
        assert findings[0].package_name == "gamma"
        assert findings[0].verdict == "reachable"
        assert findings[0].paths[0].path == [
            "pkg.app.main",
            "pkg.lib.public_api",
            "pkg.lib.Client.fetch",
            "requests.get",
            "beta.api",
            "gamma.run",
            "gamma.internal.vulnerable",
        ]
        assert findings[0].paths[0].used_summaries == ["requests", "beta", "gamma"]
        assert findings[0].paths[0].nodes[3]["package"] == "requests"
        assert findings[0].paths[0].nodes[4]["package"] == "beta"
        assert findings[0].paths[0].nodes[-1]["package"] == "gamma"
        summary = repo.dashboard_summary()
        assert summary.projects[0].dependencies == 3
        assert summary.projects[0].directDependencies == 1
        assert summary.projects[0].transitiveDependencies == 2
        assert summary.findings[0].package == "gamma"
