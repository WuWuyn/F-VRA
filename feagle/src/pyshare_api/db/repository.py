from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from pyshare_api.db import models as m
from pyshare_api.schemas import DashboardSummary, Finding, PackageRecord, Project, ScanRecord


def normalize_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _severity_label(value: str) -> str:
    value = (value or "").title()
    if value in {"Critical", "High", "Medium", "Low"}:
        return value
    return "Medium"


def _reachability_label(verdict: str) -> str:
    if verdict == "reachable":
        return "Reachable"
    if verdict == "potentially_reachable":
        return "Potentially reachable"
    if verdict == "unknown":
        return "Unknown"
    return "Not reachable"


def _relative_time(dt: datetime | None) -> str:
    if dt is None:
        return "Never"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = _now() - dt
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return "Now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    return "Yesterday" if days == 1 else f"{days} days ago"


def version_is_affected(version: str, affected_versions: list[Any], fixed_versions: list[Any]) -> bool:
    fixed = [str(item).strip() for item in fixed_versions if str(item).strip()]
    if fixed:
        try:
            parsed = Version(version)
            if any(parsed >= Version(item) for item in fixed):
                return False
        except InvalidVersion:
            return False
    if not affected_versions:
        return True
    cleaned = [str(item).strip() for item in affected_versions if str(item).strip()]
    if version in cleaned or "*" in cleaned:
        return True
    for item in cleaned:
        try:
            if Version(version) in SpecifierSet(item):
                return True
        except (InvalidSpecifier, InvalidVersion):
            continue
    return False


class FvraRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_project(self, *, name: str, repo_url: str, branch: str) -> m.Project:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Project name is required.")
        duplicate = self.session.scalars(
            select(m.Project).where(func.lower(m.Project.name) == normalized_name.lower()).limit(1)
        ).first()
        if duplicate is not None:
            raise ValueError("Project name already exists.")
        project = m.Project(name=normalized_name, repo_url=repo_url, default_branch=branch or "main")
        self.session.add(project)
        self.session.commit()
        self.session.refresh(project)
        return project

    def list_projects(self) -> list[m.Project]:
        return list(self.session.scalars(select(m.Project).order_by(m.Project.created_at.desc())))

    def get_project(self, project_id: str) -> m.Project | None:
        return self.session.get(m.Project, project_id)

    def delete_project(self, project_id: str) -> bool:
        project = self.get_project(project_id)
        if project is None:
            return False

        revision_ids = [
            row[0]
            for row in self.session.execute(
                select(m.ProjectRevision.id).where(m.ProjectRevision.project_id == project_id)
            ).all()
        ]
        scan_ids = [
            row[0]
            for row in self.session.execute(
                select(m.ScanJob.id).where(m.ScanJob.project_id == project_id)
            ).all()
        ]
        finding_ids: list[str] = []
        if scan_ids:
            finding_ids = [
                row[0]
                for row in self.session.execute(
                    select(m.ScanFinding.id).where(m.ScanFinding.scan_id.in_(scan_ids))
                ).all()
            ]
        if finding_ids:
            self.session.execute(delete(m.ReachabilityPathRow).where(m.ReachabilityPathRow.finding_id.in_(finding_ids)))
        if scan_ids:
            self.session.execute(delete(m.ScanFinding).where(m.ScanFinding.scan_id.in_(scan_ids)))
            self.session.execute(delete(m.ScanArtifact).where(m.ScanArtifact.scan_id.in_(scan_ids)))
            self.session.execute(delete(m.ScanJob).where(m.ScanJob.id.in_(scan_ids)))
        if revision_ids:
            self.session.execute(delete(m.ProjectRevisionArtifact).where(m.ProjectRevisionArtifact.project_revision_id.in_(revision_ids)))
            self.session.execute(delete(m.Dependency).where(m.Dependency.project_revision_id.in_(revision_ids)))
            self.session.execute(delete(m.ProjectRevision).where(m.ProjectRevision.id.in_(revision_ids)))
        self.session.execute(delete(m.Project).where(m.Project.id == project_id))
        self.session.commit()
        return True

    def create_scan_job(self, project_id: str, *, branch: str = "", cve_ids: list[str] | None = None) -> m.ScanJob:
        project = self.get_project(project_id)
        if project is None:
            raise KeyError(project_id)
        job = m.ScanJob(
            project_id=project_id,
            branch=branch or project.default_branch,
            requested_cve_ids=cve_ids or [],
            status="queued",
        )
        self.session.add(job)
        self.session.commit()
        self.session.refresh(job)
        return job

    def get_scan_job(self, scan_id: str) -> m.ScanJob | None:
        return self.session.get(m.ScanJob, scan_id)

    def claim_next_scan_job(self) -> m.ScanJob | None:
        query = (
            select(m.ScanJob)
            .where(m.ScanJob.status == "queued")
            .order_by(m.ScanJob.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        job = self.session.scalars(query).first()
        if job is None:
            return None
        job.status = "running"
        job.started_at = _now()
        job.heartbeat_at = job.started_at
        self.session.commit()
        self.session.refresh(job)
        return job

    def mark_scan_failed(self, job: m.ScanJob, message: str, *, step: str = "") -> None:
        job.status = "failed"
        job.error_message = message[:4000]
        job.failure_step = step[:128]
        job.completed_at = _now()
        job.heartbeat_at = job.completed_at
        self.session.commit()

    def mark_scan_completed(self, job: m.ScanJob) -> None:
        job.status = "completed"
        job.error_message = ""
        job.failure_step = ""
        job.completed_at = _now()
        job.heartbeat_at = job.completed_at
        self.session.commit()

    def heartbeat_scan(self, job: m.ScanJob, *, step: str = "") -> None:
        if step:
            job.failure_step = step[:128]
        job.heartbeat_at = _now()
        self.session.commit()

    def upsert_project_revision(
        self,
        *,
        project_id: str,
        branch: str,
        commit_sha: str,
        dependency_fingerprint: str,
        analyzer_version: str = "0.1.0",
    ) -> m.ProjectRevision:
        existing = self.session.scalars(
            select(m.ProjectRevision).where(
                m.ProjectRevision.project_id == project_id,
                m.ProjectRevision.commit_sha == commit_sha,
                m.ProjectRevision.dependency_fingerprint == dependency_fingerprint,
                m.ProjectRevision.analyzer_version == analyzer_version,
            )
        ).first()
        if existing:
            return existing
        revision = m.ProjectRevision(
            project_id=project_id,
            branch=branch,
            commit_sha=commit_sha,
            dependency_fingerprint=dependency_fingerprint,
            analyzer_version=analyzer_version,
        )
        self.session.add(revision)
        self.session.commit()
        self.session.refresh(revision)
        return revision

    def replace_dependencies(self, revision_id: str, dependencies: list[dict[str, Any]]) -> None:
        self.session.execute(delete(m.Dependency).where(m.Dependency.project_revision_id == revision_id))
        for item in dependencies:
            self.session.add(
                m.Dependency(
                    project_revision_id=revision_id,
                    ecosystem=item.get("ecosystem", "pypi"),
                    package_name=item.get("package_name", item.get("name", "")),
                    normalized_name=normalize_name(item.get("normalized_name") or item.get("package_name") or item.get("name", "")),
                    version=item.get("version", ""),
                    direct=bool(item.get("direct", False)),
                    dev=bool(item.get("dev", False)),
                    purl=item.get("purl", ""),
                )
            )
        self.session.commit()

    def upsert_package_version(self, *, ecosystem: str, normalized_name: str, version: str, python_version: str = "") -> m.PackageVersion:
        existing = self.session.scalars(
            select(m.PackageVersion).where(
                m.PackageVersion.ecosystem == ecosystem,
                m.PackageVersion.normalized_name == normalized_name,
                m.PackageVersion.version == version,
                m.PackageVersion.python_version == python_version,
            )
        ).first()
        if existing:
            return existing
        package = m.PackageVersion(
            ecosystem=ecosystem,
            normalized_name=normalized_name,
            version=version,
            python_version=python_version,
        )
        self.session.add(package)
        self.session.commit()
        self.session.refresh(package)
        return package

    def upsert_artifact(
        self,
        *,
        kind: str,
        reusable_key: str,
        payload: dict[str, Any],
        storage_root: Path,
        schema_version: str = "1",
        analyzer_version: str = "0.1.0",
        node_count: int = 0,
        edge_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> m.Artifact:
        encoded = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        content_hash = hashlib.sha256(encoded).hexdigest()
        rel_path = Path(kind) / content_hash[:2] / f"{content_hash}.json"
        path = storage_root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(encoded)
        existing = self.session.scalars(
            select(m.Artifact).where(m.Artifact.kind == kind, m.Artifact.reusable_key == reusable_key)
        ).first()
        if existing:
            existing.content_hash = content_hash
            existing.storage_uri = path.as_posix()
            existing.size_bytes = len(encoded)
            existing.node_count = node_count
            existing.edge_count = edge_count
            existing.artifact_metadata = metadata or {}
            self.session.commit()
            self.session.refresh(existing)
            return existing
        artifact = m.Artifact(
            kind=kind,
            reusable_key=reusable_key,
            schema_version=schema_version,
            analyzer_version=analyzer_version,
            content_hash=content_hash,
            storage_uri=path.as_posix(),
            size_bytes=len(encoded),
            node_count=node_count,
            edge_count=edge_count,
            artifact_metadata=metadata or {},
        )
        self.session.add(artifact)
        self.session.commit()
        self.session.refresh(artifact)
        return artifact

    def get_artifact(self, *, kind: str, reusable_key: str) -> m.Artifact | None:
        return self.session.scalars(
            select(m.Artifact).where(m.Artifact.kind == kind, m.Artifact.reusable_key == reusable_key)
        ).first()

    def link_project_artifact(self, revision_id: str, artifact_id: str) -> None:
        if not self.session.scalars(select(m.ProjectRevisionArtifact).where(
            m.ProjectRevisionArtifact.project_revision_id == revision_id,
            m.ProjectRevisionArtifact.artifact_id == artifact_id,
        )).first():
            self.session.add(m.ProjectRevisionArtifact(project_revision_id=revision_id, artifact_id=artifact_id))
            self.session.commit()

    def link_package_artifact(self, package_version_id: str, artifact_id: str) -> None:
        if not self.session.scalars(select(m.PackageVersionArtifact).where(
            m.PackageVersionArtifact.package_version_id == package_version_id,
            m.PackageVersionArtifact.artifact_id == artifact_id,
        )).first():
            self.session.add(m.PackageVersionArtifact(package_version_id=package_version_id, artifact_id=artifact_id))
            self.session.commit()

    def link_scan_artifact(self, scan_id: str, artifact_id: str) -> None:
        if not self.session.scalars(select(m.ScanArtifact).where(
            m.ScanArtifact.scan_id == scan_id,
            m.ScanArtifact.artifact_id == artifact_id,
        )).first():
            self.session.add(m.ScanArtifact(scan_id=scan_id, artifact_id=artifact_id))
            self.session.commit()

    def matching_vulnerabilities(self, revision_id: str, cve_ids: list[str] | None = None) -> list[tuple[m.Advisory, m.AdvisoryAffectedPackage, m.Dependency, list[m.VulnerableEntity]]]:
        deps = list(self.session.scalars(select(m.Dependency).where(m.Dependency.project_revision_id == revision_id)))
        wanted = {item.upper() for item in cve_ids or []}
        matches: list[tuple[m.Advisory, m.AdvisoryAffectedPackage, m.Dependency, list[m.VulnerableEntity]]] = []
        for dep in deps:
            affected_rows = list(self.session.scalars(
                select(m.AdvisoryAffectedPackage).where(
                    func.lower(m.AdvisoryAffectedPackage.ecosystem) == dep.ecosystem.lower(),
                    m.AdvisoryAffectedPackage.normalized_name == dep.normalized_name,
                )
            ))
            for affected in affected_rows:
                advisory = self.session.get(m.Advisory, affected.advisory_id)
                if advisory is None:
                    continue
                aliases = {advisory.canonical_id.upper()} | {
                    alias.alias.upper()
                    for alias in self.session.scalars(select(m.AdvisoryAlias).where(m.AdvisoryAlias.advisory_id == advisory.id))
                }
                if wanted and not aliases.intersection(wanted):
                    continue
                if not version_is_affected(dep.version, affected.affected_versions, affected.fixed_versions):
                    continue
                entities = list(self.session.scalars(
                    select(m.VulnerableEntity).where(
                        m.VulnerableEntity.advisory_id == advisory.id,
                        m.VulnerableEntity.package_name == affected.package_name,
                    )
                ))
                matches.append((advisory, affected, dep, entities))
        return matches

    def clear_scan_results(self, scan_id: str) -> None:
        self.session.execute(delete(m.ScanFinding).where(m.ScanFinding.scan_id == scan_id))
        self.session.commit()

    def add_scan_finding(
        self,
        *,
        scan_id: str,
        advisory_id: str,
        package_name: str,
        package_version: str,
        vulnerable_function: str,
        verdict: str,
        severity: str,
        summary: str,
        fixed_version: str,
        score: float,
        paths: list[dict[str, Any]],
        evidence_status: str = "unavailable",
    ) -> m.ScanFinding:
        finding = m.ScanFinding(
            scan_id=scan_id,
            advisory_id=advisory_id,
            package_name=package_name,
            package_version=package_version,
            vulnerable_function=vulnerable_function,
            verdict=verdict,
            path_count=len(paths),
            severity=_severity_label(severity),
            summary=summary,
            fixed_version=fixed_version,
            score=score,
            evidence_status=evidence_status,
        )
        self.session.add(finding)
        self.session.flush()
        for path in paths:
            self.session.add(
                m.ReachabilityPathRow(
                    finding_id=finding.id,
                    project_api=path.get("project_api", ""),
                    vulnerable_target=path.get("target", ""),
                    path=path.get("path", []),
                    used_summaries=path.get("used_summaries", []),
                    nodes=path.get("nodes", []),
                    warnings=path.get("warnings", []),
                )
            )
        self.session.commit()
        self.session.refresh(finding)
        return finding

    def dashboard_summary(self) -> DashboardSummary:
        projects = self._dashboard_projects()
        findings = self._dashboard_findings()
        packages = self._dashboard_packages()
        scans = self._dashboard_scans()
        return DashboardSummary(projects=projects, findings=findings, packages=packages, scans=scans)

    def _latest_scan(self, project_id: str, *, completed_only: bool = False) -> m.ScanJob | None:
        query = select(m.ScanJob).where(m.ScanJob.project_id == project_id)
        if completed_only:
            query = query.where(m.ScanJob.status == "completed")
        return self.session.scalars(query.order_by(m.ScanJob.created_at.desc()).limit(1)).first()

    def _scan_duration(self, scan: m.ScanJob | None) -> str:
        if scan is None or scan.started_at is None or scan.completed_at is None:
            return ""
        seconds = max(0, int((scan.completed_at - scan.started_at).total_seconds()))
        return f"{seconds}s"

    def _dashboard_projects(self) -> list[Project]:
        rows: list[Project] = []
        for project in self.list_projects():
            latest = self._latest_scan(project.id)
            latest_completed = self._latest_scan(project.id, completed_only=True)
            revision = self.session.scalars(
                select(m.ProjectRevision).where(m.ProjectRevision.project_id == project.id).order_by(m.ProjectRevision.created_at.desc()).limit(1)
            ).first()
            dependency_count = 0
            direct_count = 0
            if revision:
                dependencies = list(self.session.scalars(select(m.Dependency).where(m.Dependency.project_revision_id == revision.id)))
                dependency_count = len(dependencies)
                direct_count = sum(1 for dependency in dependencies if dependency.direct)
            scan_findings = []
            if latest_completed is not None:
                scan_findings = list(self.session.scalars(select(m.ScanFinding).where(m.ScanFinding.scan_id == latest_completed.id)))
            reachable = sum(1 for finding in scan_findings if finding.verdict == "reachable")
            risk = min(100, reachable * 20 + sum(1 for finding in scan_findings if finding.severity in {"Critical", "High"}) * 10)
            graph_nodes = 0
            graph_edges = 0
            if latest_completed is not None:
                artifact = self.session.scalars(
                    select(m.Artifact)
                    .join(m.ScanArtifact, m.ScanArtifact.artifact_id == m.Artifact.id)
                    .where(m.ScanArtifact.scan_id == latest_completed.id, m.Artifact.kind == "project-call-graph")
                    .order_by(m.Artifact.created_at.desc())
                    .limit(1)
                ).first()
                if artifact is not None:
                    graph_nodes = artifact.node_count
                    graph_edges = artifact.edge_count
            rows.append(Project(
                id=project.id,
                name=project.name,
                repository=project.repo_url,
                language="Python",
                branch=(latest.branch if latest else project.default_branch),
                riskScore=risk,
                dependencies=dependency_count,
                directDependencies=direct_count,
                transitiveDependencies=max(0, dependency_count - direct_count),
                vulnerabilities=len(scan_findings),
                reachable=reachable,
                lastScan=_relative_time(latest.completed_at or latest.created_at if latest else None),
                latestScanStatus=latest.status.capitalize() if latest else "Never",
                latestScanDuration=self._scan_duration(latest),
                graphNodes=graph_nodes,
                graphEdges=graph_edges,
            ))
        return rows

    def _dashboard_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        latest_completed_ids = [
            scan.id
            for project in self.list_projects()
            for scan in [self._latest_scan(project.id, completed_only=True)]
            if scan is not None
        ]
        if not latest_completed_ids:
            return findings
        rows = self.session.execute(
            select(m.ScanFinding, m.ScanJob, m.Project)
            .join(m.ScanJob, m.ScanFinding.scan_id == m.ScanJob.id)
            .join(m.Project, m.ScanJob.project_id == m.Project.id)
            .where(m.ScanFinding.scan_id.in_(latest_completed_ids))
            .order_by(m.ScanJob.created_at.desc())
        ).all()
        for row in rows:
            finding, _scan, project = row
            findings.append(Finding(
                id=finding.advisory_id,
                title=finding.summary or finding.advisory_id,
                package=finding.package_name,
                version=finding.package_version,
                severity=_severity_label(finding.severity),
                score=finding.score,
                reachability=_reachability_label(finding.verdict),
                pathCount=finding.path_count,
                fixedVersion=finding.fixed_version,
                project=project.name,
                projectId=project.id,
                published="",
                summary=finding.summary,
                functionName=finding.vulnerable_function,
                evidenceStatus=finding.evidence_status if finding.evidence_status in {"complete", "partial", "unavailable"} else "unavailable",
            ))
        return findings

    def _dashboard_packages(self) -> list[PackageRecord]:
        grouped: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(lambda: {"projects": set(), "direct": False, "vulnerabilities": 0})
        latest_completed_ids: list[str] = []
        for project in self.list_projects():
            revision = self.session.scalars(
                select(m.ProjectRevision).where(m.ProjectRevision.project_id == project.id).order_by(m.ProjectRevision.created_at.desc()).limit(1)
            ).first()
            if revision is not None:
                for dep in self.session.scalars(select(m.Dependency).where(m.Dependency.project_revision_id == revision.id)):
                    key = (dep.package_name, dep.version, dep.ecosystem)
                    grouped[key]["projects"].add(project.id)
                    grouped[key]["direct"] = grouped[key]["direct"] or dep.direct
            latest_completed = self._latest_scan(project.id, completed_only=True)
            if latest_completed is not None:
                latest_completed_ids.append(latest_completed.id)
        if latest_completed_ids:
            findings = self.session.scalars(select(m.ScanFinding).where(m.ScanFinding.scan_id.in_(latest_completed_ids)))
        else:
            findings = []
        for finding in findings:
            key = (finding.package_name, finding.package_version, "pypi")
            grouped[key]["vulnerabilities"] += 1
        return [
            PackageRecord(
                name=name,
                version=version,
                ecosystem=ecosystem,
                projects=len(data["projects"]),
                vulnerabilities=data["vulnerabilities"],
                direct=data["direct"],
                license="",
            )
            for (name, version, ecosystem), data in sorted(grouped.items())
        ]

    def _dashboard_scans(self) -> list[ScanRecord]:
        rows: list[ScanRecord] = []
        for scan in self.session.scalars(select(m.ScanJob).order_by(m.ScanJob.created_at.desc()).limit(20)):
            project = self.session.get(m.Project, scan.project_id)
            count = int(self.session.scalar(select(func.count()).select_from(m.ScanFinding).where(m.ScanFinding.scan_id == scan.id)) or 0)
            duration = ""
            if scan.started_at and scan.completed_at:
                seconds = max(0, int((scan.completed_at - scan.started_at).total_seconds()))
                duration = f"{seconds}s"
            rows.append(ScanRecord(
                project=project.name if project else scan.project_id,
                projectId=project.id if project else scan.project_id,
                trigger=scan.trigger,
                branch=scan.branch,
                status=scan.status.capitalize(),
                duration=duration,
                findings=count,
                date=_relative_time(scan.completed_at or scan.created_at),
            ))
        return rows
