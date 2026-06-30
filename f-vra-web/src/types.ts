export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type Reachability = 'Reachable' | 'Potentially reachable' | 'Not reachable' | 'Unknown'
export type EvidenceStatus = 'complete' | 'partial' | 'unavailable'

export type Finding = {
  id: string
  title: string
  package: string
  version: string
  severity: Severity
  score: number
  reachability: Reachability
  pathCount: number
  fixedVersion: string
  project: string
  projectId?: string
  published: string
  summary: string
  functionName: string
  evidenceStatus?: EvidenceStatus
}

export type Project = {
  id: string
  name: string
  repository: string
  language: string
  branch: string
  riskScore: number
  dependencies: number
  directDependencies: number
  transitiveDependencies: number
  vulnerabilities: number
  reachable: number
  lastScan: string
  latestScanStatus: string
  latestScanDuration: string
  graphNodes: number
  graphEdges: number
}

export type PackageRecord = {
  name: string
  version: string
  ecosystem: string
  projects: number
  vulnerabilities: number
  direct: boolean
  license: string
}

export type ScanRecord = {
  project: string
  projectId?: string
  trigger: string
  branch: string
  status: string
  duration: string
  findings: number
  date: string
}

export type DashboardSummary = {
  projects: Project[]
  findings: Finding[]
  packages: PackageRecord[]
  scans: ScanRecord[]
}

export type CreateProjectInput = {
  name: string
  repoUrl: string
  branch: string
}

export type ScanStatus = {
  id: string
  projectId: string
  status: string
  branch: string
  commitSha: string
  requestedCveIds: string[]
  errorMessage: string
  findings: number
  failureStep: string
  retryCount: number
}

export type FindingPathNode = {
  name: string
  kind: string
  package: string
  file: string
  line: number
  callExpr: string
  sourceSnippet: string
  sourceStartLine: number
  confidence: number
}

export type FindingPath = {
  projectApi: string
  vulnerableTarget: string
  path: string[]
  usedSummaries: string[]
  nodes: FindingPathNode[]
  warnings: Record<string, unknown>[]
}

