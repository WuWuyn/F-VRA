import type { CreateProjectInput, DashboardSummary, Finding, FindingPath, PackageRecord, Project, ScanRecord, ScanStatus } from '../types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Content-Type', 'application/json')

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers,
  })

  if (!response.ok) {
    const message = await response.text()
    throw new ApiError(response.status, message || `API request failed with ${response.status}`)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function getApiHealth() {
  return request<{ status: string; service: string }>('/health')
}

export function getDashboardSummary() {
  return request<DashboardSummary>('/dashboard/summary')
}

export function createProject(input: CreateProjectInput) {
  return request<Project>('/projects', {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

export function deleteProject(projectId: string) {
  return request<void>(`/projects/${projectId}`, {
    method: 'DELETE',
  })
}

export function createProjectScan(projectId: string, cveIds: string[] = []) {
  return request<ScanStatus>(`/projects/${projectId}/scans`, {
    method: 'POST',
    body: JSON.stringify({ cveIds }),
  })
}

export function getScan(scanId: string) {
  return request<ScanStatus>(`/scans/${scanId}`)
}

export function getFindingPaths(findingId: string) {
  return request<FindingPath[]>(`/findings/${encodeURIComponent(findingId)}/paths`)
}

export function listProjects() {
  return request<Project[]>('/projects')
}

export function listVulnerabilities(project?: string) {
  const query = project ? `?project=${encodeURIComponent(project)}` : ''
  return request<Finding[]>(`/vulnerabilities${query}`)
}

export function listPackages() {
  return request<PackageRecord[]>('/packages')
}

export function listScans(project?: string) {
  const query = project ? `?project=${encodeURIComponent(project)}` : ''
  return request<ScanRecord[]>(`/scans${query}`)
}
