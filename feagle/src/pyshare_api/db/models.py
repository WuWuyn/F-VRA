from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pyshare_api.db.session import Base


def _id() -> str:
    return uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


JsonType = JSON().with_variant(JSONB, "postgresql")


class RawAdvisorySource(Base):
    __tablename__ = "raw_advisory_sources"
    __table_args__ = (UniqueConstraint("source", "source_record_id", "sha256"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    raw_payload: Mapped[dict] = mapped_column(JsonType, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    canonical_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    aliases: Mapped[list["AdvisoryAlias"]] = relationship(back_populates="advisory", cascade="all, delete-orphan")
    affected_packages: Mapped[list["AdvisoryAffectedPackage"]] = relationship(back_populates="advisory", cascade="all, delete-orphan")
    vulnerable_entities: Mapped[list["VulnerableEntity"]] = relationship(back_populates="advisory", cascade="all, delete-orphan")


class AdvisoryAlias(Base):
    __tablename__ = "advisory_aliases"
    __table_args__ = (UniqueConstraint("alias"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alias_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    advisory: Mapped[Advisory] = relationship(back_populates="aliases")


class AdvisoryReference(Base):
    __tablename__ = "advisory_references"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    reference_type: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    tags: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)


class AdvisoryAffectedPackage(Base):
    __tablename__ = "advisory_affected_packages"
    __table_args__ = (UniqueConstraint("advisory_id", "ecosystem", "package_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(64), default="pypi", nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    affected_versions: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    fixed_versions: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    advisory: Mapped[Advisory] = relationship(back_populates="affected_packages")
    ranges: Mapped[list["AffectedRange"]] = relationship(back_populates="affected_package", cascade="all, delete-orphan")


class AffectedRange(Base):
    __tablename__ = "affected_ranges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    affected_package_id: Mapped[str] = mapped_column(ForeignKey("advisory_affected_packages.id", ondelete="CASCADE"), nullable=False, index=True)
    range_type: Mapped[str] = mapped_column(String(32), default="ECOSYSTEM", nullable=False)
    repo_url: Mapped[str] = mapped_column(Text, default="", nullable=False)
    events: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    affected_package: Mapped[AdvisoryAffectedPackage] = relationship(back_populates="ranges")


class SeverityRecord(Base):
    __tablename__ = "severity_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    severity_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    vector: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(32), default="", nullable=False)


class WeaknessRecord(Base):
    __tablename__ = "weakness_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)


class VulnerableEntity(Base):
    __tablename__ = "vulnerable_entities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"), nullable=False, index=True)
    affected_package_id: Mapped[str | None] = mapped_column(ForeignKey("advisory_affected_packages.id", ondelete="SET NULL"), index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), default="function", nullable=False)
    role: Mapped[str] = mapped_column(String(64), default="sink", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    advisory: Mapped[Advisory] = relationship(back_populates="vulnerable_entities")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    __table_args__ = (Index("uq_projects_name_lower", func.lower(name), unique=True),)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    default_branch: Mapped[str] = mapped_column(String(255), default="main", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    revisions: Mapped[list["ProjectRevision"]] = relationship(back_populates="project")
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="project")


class ProjectRevision(Base):
    __tablename__ = "project_revisions"
    __table_args__ = (UniqueConstraint("project_id", "commit_sha", "dependency_fingerprint", "analyzer_version"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    branch: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dependency_fingerprint: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(64), default="0.1.0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    project: Mapped[Project] = relationship(back_populates="revisions")


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    project_revision_id: Mapped[str] = mapped_column(ForeignKey("project_revisions.id", ondelete="CASCADE"), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(64), default="pypi", nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    direct: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    dev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    purl: Mapped[str] = mapped_column(Text, default="", nullable=False)


class PackageVersion(Base):
    __tablename__ = "package_versions"
    __table_args__ = (UniqueConstraint("ecosystem", "normalized_name", "version", "python_version"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    ecosystem: Mapped[str] = mapped_column(String(64), default="pypi", nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    python_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("kind", "reusable_key"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reusable_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(32), default="1", nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(64), default="0.1.0", nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    edge_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    artifact_metadata: Mapped[dict] = mapped_column("metadata", JsonType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class ProjectRevisionArtifact(Base):
    __tablename__ = "project_revision_artifacts"
    __table_args__ = (UniqueConstraint("project_revision_id", "artifact_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    project_revision_id: Mapped[str] = mapped_column(ForeignKey("project_revisions.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False)


class PackageVersionArtifact(Base):
    __tablename__ = "package_version_artifacts"
    __table_args__ = (UniqueConstraint("package_version_id", "artifact_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    package_version_id: Mapped[str] = mapped_column(ForeignKey("package_versions.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    branch: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    requested_cve_ids: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(64), default="Manual scan", nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_step: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    project: Mapped[Project] = relationship(back_populates="scan_jobs")
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"
    __table_args__ = (UniqueConstraint("scan_id", "artifact_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False)


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    advisory_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_version: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    vulnerable_function: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False, index=True)
    path_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="Medium", nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fixed_version: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(32), default="unavailable", nullable=False)
    scan: Mapped[ScanJob] = relationship(back_populates="findings")
    paths: Mapped[list["ReachabilityPathRow"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class ReachabilityPathRow(Base):
    __tablename__ = "reachability_paths"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("scan_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    project_api: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    vulnerable_target: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    path: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    used_summaries: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    nodes: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    warnings: Mapped[list] = mapped_column(JsonType, default=list, nullable=False)
    finding: Mapped[ScanFinding] = relationship(back_populates="paths")
