import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { icons } from '../components/icons'
import { MetricCard, PageHeader, RiskBadge } from '../components/ui'
import { createProject, createProjectScan, deleteProject } from '../lib/api'
import type { Project } from '../types'

export function ProjectsPage({ projects, onChanged }: { projects: Project[]; onChanged: () => void | Promise<void> }) {
  const [query, setQuery] = useState('')
  const [name, setName] = useState('')
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [submitting, setSubmitting] = useState(false)
  const [deletingId, setDeletingId] = useState('')
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')
  const filtered = useMemo(() => projects.filter((project) => `${project.name} ${project.repository} ${project.language}`.toLowerCase().includes(query.toLowerCase())), [projects, query])
  const atRisk = projects.filter((project) => project.riskScore >= 50).length
  const reachable = projects.reduce((total, project) => total + project.reachable, 0)
  const scanned = projects.filter((project) => project.latestScanStatus !== 'Never').length
  const scanCoverage = projects.length ? Math.round((scanned / projects.length) * 100) : 0

  const submitProject = async (event: FormEvent) => {
    event.preventDefault()
    setSubmitting(true)
    setError('')
    setStatus('')
    try {
      const inferredName = repoUrl.replace(/\/$/, '').split('/').pop()?.replace(/\.git$/, '') || 'New project'
      const project = await createProject({ name: name.trim() || inferredName, repoUrl, branch })
      const scan = await createProjectScan(project.id)
      setStatus(`Project added. Initial scan ${scan.status}.`)
      await onChanged()
      window.location.assign(`#/project/${project.id}`)
    } catch {
      setError('Could not add and scan this Git repository. Check the URL, branch, and API connection.')
    } finally {
      setSubmitting(false)
    }
  }

  const removeProject = async (project: Project) => {
    const confirmed = window.confirm(`Remove ${project.name}? This deletes its scans and findings from the server.`)
    if (!confirmed) return
    setDeletingId(project.id)
    setError('')
    setStatus('')
    try {
      await deleteProject(project.id)
      await onChanged()
      setStatus(`${project.name} removed.`)
    } catch {
      setError(`Could not remove ${project.name}.`)
    } finally {
      setDeletingId('')
    }
  }

  const openProject = (projectId: string) => window.location.assign(`#/project/${projectId}`)

  return (
    <>
      <PageHeader eyebrow="Application portfolio" title="Projects" description="Monitor dependency risk and vulnerable code reachability for every repository." />
      <form className="panel project-create-panel" onSubmit={submitProject}>
        <div><h2>Add project</h2><p>Register a cloneable Git repository. F-VRA queues the first server-side scan immediately.</p></div>
        <label><span>Name</span><input value={name} onChange={(event) => setName(event.target.value)} placeholder="my-python-service" /></label>
        <label><span>Git URL</span><input value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} placeholder="https://github.com/org/repo.git" required /></label>
        <label><span>Branch</span><input value={branch} onChange={(event) => setBranch(event.target.value)} placeholder="main" /></label>
        <button className="primary-button" disabled={submitting}>{submitting ? 'Adding and scanning...' : <>{icons.plus} Add and scan</>}</button>
        {error && <p className="form-error">{error}</p>}
        {status && <p className="form-success">{status}</p>}
      </form>
      <section className="metric-grid">
        <MetricCard icon={icons.folder} label="Total projects" value={projects.length} detail={`${projects.length} active projects`} />
        <MetricCard icon={icons.shield} label="At risk" value={atRisk} detail="Risk score above 50" tone="navy" />
        <MetricCard icon={icons.branch} label="Reachable CVEs" value={reachable} detail="Across connected projects" tone="slate" />
        <MetricCard icon={icons.clock} label="Scan coverage" value={`${scanCoverage}%`} detail={`${scanned} of ${projects.length} projects have scan records`} tone="sky" />
      </section>
      <section className="panel">
        <div className="table-toolbar">
          <div><h2>All projects</h2><p>Sorted by highest risk score</p></div>
          <label className="search-field wide">{icons.search}<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects" /></label>
        </div>
        <div className="data-table project-table">
          <div className="table-head"><span>Project</span><span>Risk</span><span>Dependencies</span><span>Vulnerabilities</span><span>Reachable</span><span>Last scan</span><span>Actions</span></div>
          {[...filtered].sort((a, b) => b.riskScore - a.riskScore).map((project) => (
            <div className="table-row clickable-row" key={project.id} onClick={() => openProject(project.id)} onKeyDown={(event) => event.key === 'Enter' && openProject(project.id)} role="button" tabIndex={0}>
              <span className="entity-cell"><i className="project-avatar">{project.name.slice(0, 2).toUpperCase()}</i><span><strong>{project.name}</strong><small>{project.repository} / {project.branch} / {project.language}</small></span></span>
              <RiskBadge score={project.riskScore} />
              <span>{project.dependencies}</span><span>{project.vulnerabilities}</span><span className="reachable-count">{project.reachable}</span><span className="muted">{project.lastScan}</span>
              <span className="row-actions">
                <button className="secondary-button compact-action" onClick={(event) => { event.stopPropagation(); openProject(project.id) }}>Open</button>
                <button className="danger-button compact-action" disabled={deletingId === project.id} onClick={(event) => { event.stopPropagation(); removeProject(project) }}>{deletingId === project.id ? 'Removing...' : 'Remove'}</button>
              </span>
            </div>
          ))}
        </div>
      </section>
    </>
  )
}
