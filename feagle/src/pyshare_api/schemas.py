from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low"]
Reachability = Literal["Reachable", "Potentially reachable", "Not reachable", "Unknown"]
EvidenceStatus = Literal["complete", "partial", "unavailable"]


class Project(BaseModel):
    id: str
    name: str
    repository: str
    language: str
    branch: str
    riskScore: int
    dependencies: int
    directDependencies: int = 0
    transitiveDependencies: int = 0
    vulnerabilities: int
    reachable: int
    lastScan: str
    latestScanStatus: str = "Never"
    latestScanDuration: str = ""
    graphNodes: int = 0
    graphEdges: int = 0


class Finding(BaseModel):
    id: str
    title: str
    package: str
    version: str
    severity: Severity
    score: float
    reachability: Reachability
    pathCount: int
    fixedVersion: str
    project: str
    projectId: str = ""
    published: str
    summary: str
    functionName: str
    evidenceStatus: EvidenceStatus = "unavailable"


class PackageRecord(BaseModel):
    name: str
    version: str
    ecosystem: str
    projects: int
    vulnerabilities: int
    direct: bool
    license: str


class ScanRecord(BaseModel):
    project: str
    projectId: str = ""
    trigger: str
    branch: str
    status: str
    duration: str
    findings: int
    date: str


class DashboardSummary(BaseModel):
    projects: list[Project]
    findings: list[Finding]
    packages: list[PackageRecord]
    scans: list[ScanRecord]


class CreateProjectRequest(BaseModel):
    name: str
    repoUrl: str
    branch: str = "main"


class CreateScanRequest(BaseModel):
    cveIds: list[str] = Field(default_factory=list)


class ScanStatus(BaseModel):
    id: str
    projectId: str
    status: str
    branch: str
    commitSha: str = ""
    requestedCveIds: list[str] = Field(default_factory=list)
    errorMessage: str = ""
    findings: int = 0
    failureStep: str = ""
    retryCount: int = 0


class FindingPathNode(BaseModel):
    name: str
    kind: str = "application"
    package: str = ""
    file: str = ""
    line: int = 0
    callExpr: str = ""
    sourceSnippet: str = ""
    sourceStartLine: int = 0
    confidence: float = 1.0


class FindingPath(BaseModel):
    projectApi: str
    vulnerableTarget: str
    path: list[str] = Field(default_factory=list)
    usedSummaries: list[str] = Field(default_factory=list)
    nodes: list[FindingPathNode] = Field(default_factory=list)
    warnings: list[dict] = Field(default_factory=list)


class ScanRequest(BaseModel):
    projectId: str | None = None
    projectPath: str = Field("", description="Absolute or server-mounted project path to scan.")
    branch: str | None = None
    cveIds: list[str] = Field(default_factory=list)


class ReachabilityCheckResponse(BaseModel):
    verdict: str
    vulnerableTargets: list[str] = Field(default_factory=list)
    paths: list[FindingPath] = Field(default_factory=list)
    warnings: dict = Field(default_factory=dict)
    queryTimeMs: float = 0.0


class ReachabilityCheckRequest(BaseModel):
    projectPath: str
    vulnerableFunctions: list[str] = Field(default_factory=list)
    packageReports: dict[str, str] = Field(default_factory=dict)
    maxDepth: int = 25
    maxPaths: int = 100


class LocalizeCveRequest(BaseModel):
    cveId: str
    cweId: str | None = None
    patchPath: str | None = None
    autoResolvePatch: bool = True
    topK: int = 20


class LocalizeCveResponse(BaseModel):
    cveId: str
    entities: list[dict] = Field(default_factory=list)
    source: str = "database"


class JobAccepted(BaseModel):
    jobId: str
    status: Literal["queued"]
    message: str


class CliDependency(BaseModel):
    ecosystem: str = "pypi"
    name: str = ""
    normalizedName: str = ""
    version: str = ""
    direct: bool = False
    dev: bool = False
    dependencies: list[str] = Field(default_factory=list)
    purl: str = ""


class CliScanPlanRequest(BaseModel):
    dependencies: list[CliDependency] = Field(default_factory=list)
    cveIds: list[str] = Field(default_factory=list)
    usageRoots: list[str] = Field(default_factory=list)


class CliAdvisoryMatch(BaseModel):
    advisoryId: str
    title: str = ""
    summary: str = ""
    package: str
    normalizedPackage: str
    version: str
    fixedVersion: str = ""
    severity: str = "Medium"
    score: float = 5.0
    vulnerableFunctions: list[str] = Field(default_factory=list)


class CliPackageSummary(BaseModel):
    root: str
    package: str
    version: str
    reusableKey: str
    summary: dict = Field(default_factory=dict)


class CliScanPlanResponse(BaseModel):
    matches: list[CliAdvisoryMatch] = Field(default_factory=list)
    packageSummaries: list[CliPackageSummary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
