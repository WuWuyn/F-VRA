from __future__ import annotations

from urllib.parse import urlparse

from pyshare_api.worker import artifact_root
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, status

from pyshare_api.db import models as m
from pyshare_api.db.repository import FvraRepository
from pyshare_api.db.session import get_session
from pyshare_api.schemas import (
    CreateProjectRequest,
    DashboardSummary,
    Finding,
    FindingPath,
    PackageRecord,
    Project,
    ScanRecord,
)

router = APIRouter()


def repo(session: Session = Depends(get_session)) -> FvraRepository:
    return FvraRepository(session)


def _validate_public_git_url(repo_url: str) -> None:
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Pilot projects must use a public HTTPS Git URL.")
    host = parsed.hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise HTTPException(status_code=400, detail="Local/private Git URLs are blocked for pilot web submissions.")


@router.get("/health")
def health(session: Session = Depends(get_session)) -> dict[str, str]:
    session.execute(select(1))
    latest_running = session.scalars(
        select(m.ScanJob).where(m.ScanJob.status == "running").order_by(m.ScanJob.heartbeat_at.desc()).limit(1)
    ).first()
    artifact_ok = artifact_root().exists() or artifact_root().parent.exists()
    return {
        "status": "ok" if artifact_ok else "degraded",
        "service": "f-vra-api",
        "database": "ok",
        "artifactRoot": "ok" if artifact_ok else "missing",
        "workerHeartbeat": latest_running.heartbeat_at.isoformat() if latest_running and latest_running.heartbeat_at else "",
    }


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(repository: FvraRepository = Depends(repo)) -> DashboardSummary:
    return repository.dashboard_summary()


@router.post("/projects", response_model=Project, status_code=status.HTTP_201_CREATED)
def create_project(request: CreateProjectRequest, repository: FvraRepository = Depends(repo)) -> Project:
    _validate_public_git_url(request.repoUrl)
    try:
        project = repository.create_project(name=request.name.strip() or request.repoUrl.rstrip("/").split("/")[-1], repo_url=request.repoUrl, branch=request.branch)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return Project(
        id=project.id,
        name=project.name,
        repository=project.repo_url,
        language="Python",
        branch=project.default_branch,
        riskScore=0,
        dependencies=0,
        directDependencies=0,
        transitiveDependencies=0,
        vulnerabilities=0,
        reachable=0,
        lastScan="Never",
        latestScanStatus="Never",
        latestScanDuration="",
        graphNodes=0,
        graphEdges=0,
    )


@router.get("/projects", response_model=list[Project])
def list_projects(repository: FvraRepository = Depends(repo)) -> list[Project]:
    return repository.dashboard_summary().projects


@router.get("/projects/{project_id}", response_model=Project)
def get_project(project_id: str, repository: FvraRepository = Depends(repo)) -> Project:
    for project in repository.dashboard_summary().projects:
        if project.id == project_id:
            return project
    raise HTTPException(status_code=404, detail="Project not found")


@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, repository: FvraRepository = Depends(repo)) -> None:
    if not repository.delete_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")


@router.get("/projects/{project_id}/findings", response_model=list[Finding])
def get_project_findings(project_id: str, repository: FvraRepository = Depends(repo)) -> list[Finding]:
    project = repository.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return [finding for finding in repository.dashboard_summary().findings if finding.projectId == project_id]


@router.get("/vulnerabilities", response_model=list[Finding])
def list_vulnerabilities(project: str | None = None, repository: FvraRepository = Depends(repo)) -> list[Finding]:
    findings = repository.dashboard_summary().findings
    if project is None:
        return findings
    return [finding for finding in findings if finding.project == project or finding.projectId == project]


@router.get("/findings/{finding_id}/paths", response_model=list[FindingPath])
def get_finding_paths(finding_id: str, session: Session = Depends(get_session)) -> list[FindingPath]:
    finding = session.get(m.ScanFinding, finding_id)
    if finding is None:
        finding = session.scalars(
            select(m.ScanFinding)
            .join(m.ScanJob, m.ScanFinding.scan_id == m.ScanJob.id)
            .where(m.ScanFinding.advisory_id == finding_id)
            .order_by(m.ScanJob.created_at.desc())
        ).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return [
        FindingPath(
            projectApi=path.project_api,
            vulnerableTarget=path.vulnerable_target,
            path=path.path,
            usedSummaries=path.used_summaries,
            nodes=path.nodes,
            warnings=path.warnings,
        )
        for path in finding.paths
    ]


@router.get("/packages", response_model=list[PackageRecord])
def list_packages(repository: FvraRepository = Depends(repo)) -> list[PackageRecord]:
    return repository.dashboard_summary().packages


@router.get("/scans", response_model=list[ScanRecord])
def list_scans(project: str | None = None, repository: FvraRepository = Depends(repo)) -> list[ScanRecord]:
    scans = repository.dashboard_summary().scans
    if project is None:
        return scans
    return [scan for scan in scans if scan.project == project or scan.projectId == project]
