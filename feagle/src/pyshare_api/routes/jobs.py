from __future__ import annotations

import json
import re
from uuid import uuid4

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pyshare_api.db import models as m
from pyshare_api.db.repository import FvraRepository, normalize_name, version_is_affected
from pyshare_api.db.session import get_session
from pyshare_client.reachability.service import check_transitive_reachability
from pyshare_api.schemas import (
    CliAdvisoryMatch,
    CliDependency,
    CliPackageSummary,
    CliScanPlanRequest,
    CliScanPlanResponse,
    CreateScanRequest,
    JobAccepted,
    FindingPath,
    LocalizeCveResponse,
    LocalizeCveRequest,
    ReachabilityCheckRequest,
    ReachabilityCheckResponse,
    ScanRequest,
    ScanStatus,
)

router = APIRouter()


def _dependency_name(raw: str) -> str:
    return re.split(r"[<>=!~;\\[\\], ]", str(raw).strip(), maxsplit=1)[0].replace("_", "-").lower()


def _dependency_root(dependency: CliDependency) -> str:
    return normalize_name(dependency.normalizedName or dependency.name).replace("-", "_")


def _relevant_summary_dependencies(dependencies: list[CliDependency], usage_roots: list[str], matched_names: set[str]) -> list[CliDependency]:
    by_name = {
        normalize_name(dep.normalizedName or dep.name): dep
        for dep in dependencies
        if dep.normalizedName or dep.name
    }
    wanted = {normalize_name(item) for item in matched_names}
    wanted.update(normalize_name(root) for root in usage_roots if normalize_name(root) in by_name)

    changed = True
    while changed:
        changed = False
        for name, dep in by_name.items():
            child_names = {_dependency_name(item) for item in dep.dependencies}
            if name not in wanted and child_names.intersection(wanted):
                wanted.add(name)
                changed = True
    return [dep for name, dep in by_name.items() if name in wanted]


def _severity_for(session: Session, advisory_id: str) -> tuple[str, float]:
    record = session.scalars(select(m.SeverityRecord).where(m.SeverityRecord.advisory_id == advisory_id)).first()
    if record is None:
        return "Medium", 5.0
    return record.severity or "Medium", float(record.score if record.score is not None else 5.0)


def _summary_artifact_for(session: Session, dependency: CliDependency) -> m.Artifact | None:
    ecosystem = dependency.ecosystem or "pypi"
    normalized = normalize_name(dependency.normalizedName or dependency.name)
    prefix = f"{ecosystem}:{normalized}:{dependency.version}:py"
    return session.scalars(
        select(m.Artifact)
        .where(m.Artifact.kind == "package-summary", m.Artifact.reusable_key.like(f"{prefix}%"))
        .order_by(m.Artifact.created_at.desc())
        .limit(1)
    ).first()


def _accepted(kind: str) -> JobAccepted:
    return JobAccepted(
        jobId=f"{kind}-{uuid4().hex[:12]}",
        status="queued",
        message="Request accepted by the API contract. Wire this job to the PyShare service runner next.",
    )


def _scan_status(session: Session, job: m.ScanJob) -> ScanStatus:
    findings = int(session.scalar(select(func.count()).select_from(m.ScanFinding).where(m.ScanFinding.scan_id == job.id)) or 0)
    return ScanStatus(
        id=job.id,
        projectId=job.project_id,
        status=job.status,
        branch=job.branch,
        commitSha=job.commit_sha,
        requestedCveIds=job.requested_cve_ids,
        errorMessage=job.error_message,
        findings=findings,
        failureStep=job.failure_step,
        retryCount=job.retry_count,
    )


@router.post("/projects/{project_id}/scans", response_model=ScanStatus, status_code=status.HTTP_202_ACCEPTED)
def create_project_scan(project_id: str, request: CreateScanRequest, session: Session = Depends(get_session)) -> ScanStatus:
    repository = FvraRepository(session)
    try:
        job = repository.create_scan_job(project_id, cve_ids=request.cveIds)
    except KeyError:
        raise HTTPException(status_code=404, detail="Project not found") from None
    return _scan_status(session, job)


@router.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> ScanStatus:
    job = session.get(m.ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_status(session, job)


@router.post("/cli/scan-plan", response_model=CliScanPlanResponse)
def cli_scan_plan(request: CliScanPlanRequest, session: Session = Depends(get_session)) -> CliScanPlanResponse:
    wanted = {item.upper() for item in request.cveIds}
    matches: list[CliAdvisoryMatch] = []
    matched_names: set[str] = set()
    warnings: list[str] = []

    for dependency in request.dependencies:
        normalized = normalize_name(dependency.normalizedName or dependency.name)
        if not normalized or not dependency.version:
            continue
        affected_rows = list(session.scalars(
            select(m.AdvisoryAffectedPackage).where(
                func.lower(m.AdvisoryAffectedPackage.ecosystem) == (dependency.ecosystem or "pypi").lower(),
                m.AdvisoryAffectedPackage.normalized_name == normalized,
            )
        ))
        for affected in affected_rows:
            advisory = session.get(m.Advisory, affected.advisory_id)
            if advisory is None:
                continue
            aliases = {advisory.canonical_id.upper()} | {
                alias.alias.upper()
                for alias in session.scalars(select(m.AdvisoryAlias).where(m.AdvisoryAlias.advisory_id == advisory.id))
            }
            if wanted and not aliases.intersection(wanted):
                continue
            if not version_is_affected(dependency.version, affected.affected_versions, affected.fixed_versions):
                continue
            entities = list(session.scalars(
                select(m.VulnerableEntity).where(
                    m.VulnerableEntity.advisory_id == advisory.id,
                    m.VulnerableEntity.package_name == affected.package_name,
                )
            ))
            severity, score = _severity_for(session, advisory.id)
            fixed_versions = [str(item) for item in affected.fixed_versions if str(item)]
            matches.append(CliAdvisoryMatch(
                advisoryId=advisory.canonical_id,
                title=advisory.title,
                summary=advisory.description or advisory.title or advisory.canonical_id,
                package=dependency.name or affected.package_name,
                normalizedPackage=normalized,
                version=dependency.version,
                fixedVersion=fixed_versions[0] if fixed_versions else "",
                severity=severity,
                score=score,
                vulnerableFunctions=[entity.name for entity in entities if entity.name],
            ))
            matched_names.add(normalized)

    summaries: list[CliPackageSummary] = []
    for dependency in _relevant_summary_dependencies(request.dependencies, request.usageRoots, matched_names):
        artifact = _summary_artifact_for(session, dependency)
        if artifact is None:
            warnings.append(f"package summary unavailable: {dependency.name or dependency.normalizedName}=={dependency.version}")
            continue
        try:
            payload = json.loads(Path(artifact.storage_uri).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"package summary unreadable: {artifact.reusable_key}: {exc}")
            continue
        summary = payload.get("summary") or {}
        summaries.append(CliPackageSummary(
            root=_dependency_root(dependency),
            package=dependency.name or dependency.normalizedName,
            version=dependency.version,
            reusableKey=artifact.reusable_key,
            summary=summary,
        ))

    return CliScanPlanResponse(matches=matches, packageSummaries=summaries, warnings=warnings)


@router.post("/scans", response_model=ScanStatus, status_code=status.HTTP_202_ACCEPTED)
def create_scan(request: ScanRequest, session: Session = Depends(get_session)) -> ScanStatus:
    if not request.projectId:
        raise HTTPException(status_code=400, detail="projectId is required for pilot scan creation.")
    repository = FvraRepository(session)
    try:
        job = repository.create_scan_job(request.projectId, branch=request.branch or "", cve_ids=request.cveIds)
    except KeyError:
        raise HTTPException(status_code=404, detail="Project not found") from None
    return _scan_status(session, job)


@router.post("/reachability/check", response_model=ReachabilityCheckResponse)
def check_reachability(request: ReachabilityCheckRequest) -> ReachabilityCheckResponse:
    project = Path(request.projectPath)
    if not project.exists():
        raise HTTPException(status_code=404, detail="Project path not found on the server.")
    result = check_transitive_reachability(
        project,
        set(request.vulnerableFunctions),
        max_depth=request.maxDepth,
        max_paths=request.maxPaths,
    )
    return ReachabilityCheckResponse(
        verdict=result.verdict.value,
        vulnerableTargets=result.vulnerable_targets,
        paths=[
            FindingPath(
                projectApi=path.project_api,
                vulnerableTarget=path.vulnerable_target,
                path=path.tpl_chain,
                usedSummaries=path.used_summaries,
            )
            for path in result.paths
        ],
        warnings=result.analysis_warnings,
        queryTimeMs=result.query_time_ms,
    )


@router.post("/localization/cve", response_model=LocalizeCveResponse)
def localize_cve(request: LocalizeCveRequest, session: Session = Depends(get_session)) -> LocalizeCveResponse:
    wanted = request.cveId.upper()
    advisory = session.scalars(select(m.Advisory).where(func.upper(m.Advisory.canonical_id) == wanted)).first()
    if advisory is None:
        alias = session.scalars(select(m.AdvisoryAlias).where(func.upper(m.AdvisoryAlias.alias) == wanted)).first()
        advisory = session.get(m.Advisory, alias.advisory_id) if alias else None
    if advisory is None:
        raise HTTPException(status_code=404, detail="Advisory not found in database.")
    entities = [
        {
            "package": entity.package_name,
            "name": entity.name,
            "entityType": entity.entity_type,
            "role": entity.role,
            "confidence": entity.confidence,
            "evidence": entity.evidence,
        }
        for entity in session.scalars(select(m.VulnerableEntity).where(m.VulnerableEntity.advisory_id == advisory.id))
    ]
    return LocalizeCveResponse(cveId=advisory.canonical_id, entities=entities)
