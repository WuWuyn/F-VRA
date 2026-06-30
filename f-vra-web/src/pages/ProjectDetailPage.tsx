import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Icon } from '../components/Icon'
import { ImpactGraph } from '../components/ImpactGraph'
import { icons } from '../components/icons'
import { EmptyState, ReachabilityBadge, SeverityBadge } from '../components/ui'
import { createProjectScan, deleteProject, getFindingPaths, getScan } from '../lib/api'
import { showInDevelopment } from '../lib/feedback'
import type { Finding, FindingPath, Project } from '../types'

export function ProjectDetailPage({ projectId, projects, findings, onChanged }: { projectId: string; projects: Project[]; findings: Finding[]; onChanged: () => void | Promise<void> }) {
  const project = projects.find((item) => item.id === projectId) ?? projects[0]
  const projectFindings = useMemo(() => project ? findings.filter((item) => item.projectId === project.id || item.project === project.name) : [], [findings, project])
  const [activeFindingId, setActiveFindingId] = useState(projectFindings[0]?.id ?? '')
  const [filter, setFilter] = useState('All')
  const [graphMode, setGraphMode] = useState<'Path' | 'Code'>('Path')
  const [scanStatus, setScanStatus] = useState('')
  const [scanning, setScanning] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [paths, setPaths] = useState<FindingPath[]>([])
  const [activePathIndex, setActivePathIndex] = useState(0)
  const [pathStatus, setPathStatus] = useState('')
  const activeFinding = projectFindings.find((item) => item.id === activeFindingId) ?? projectFindings[0]
  const visibleFindings = useMemo(() => projectFindings.filter((item) => filter === 'All' || item.reachability.startsWith(filter)), [filter, projectFindings])
  const activePath = paths[activePathIndex] ?? paths[0]

  useEffect(() => {
    if (!activeFinding) return
    let cancelled = false
    getFindingPaths(activeFinding.id)
      .then((rows) => {
        if (cancelled) return
        setPaths(rows)
        setActivePathIndex(0)
        setPathStatus(rows.length ? '' : 'No persisted path evidence')
      })
      .catch(() => {
        if (cancelled) return
        setPaths([])
        setActivePathIndex(0)
        setPathStatus('Path evidence unavailable')
      })
    return () => {
      cancelled = true
    }
  }, [activeFinding])

  const startScan = async () => {
    if (!project || scanning) return
    setScanning(true)
    setScanStatus('Queueing scan...')
    try {
      const scan = await createProjectScan(project.id)
      setScanStatus(`Scan ${scan.status}`)
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const current = await getScan(scan.id)
        setScanStatus(`Scan ${current.status}${current.findings ? ` with ${current.findings} findings` : ''}`)
        if (current.status === 'completed' || current.status === 'failed') break
        await new Promise((resolve) => window.setTimeout(resolve, 1500))
      }
      await onChanged()
    } catch {
      setScanStatus('Could not start scan')
    } finally {
      setScanning(false)
    }
  }

  const removeProject = async () => {
    if (!project) return
    const confirmed = window.confirm(`Remove ${project.name}? This deletes its scans and findings from the server.`)
    if (!confirmed) return
    setRemoving(true)
    try {
      await deleteProject(project.id)
      await onChanged()
      window.location.assign('#/projects')
    } catch {
      setScanStatus('Could not remove project')
    } finally {
      setRemoving(false)
    }
  }

  if (!project) return <EmptyState title="Project unavailable" description="The API did not return any projects to display." />
  if (!activeFinding) return <ProjectEmptyState project={project} scanStatus={scanStatus} scanning={scanning} removing={removing} onScan={startScan} onRemove={removeProject} />

  return (
    <>
      <ProjectHeading project={project} scanStatus={scanStatus} scanning={scanning} removing={removing} onScan={startScan} onRemove={removeProject} />
      <section className="metric-grid">
        <article className="metric-card risk-card"><div className="metric-icon navy">{icons.shield}</div><div><span>Risk score</span><strong>{project.riskScore} <small>/ 100</small></strong><p>Computed from latest completed scan</p></div><div className="risk-ring"><span>{riskLabelFor(project.riskScore)}</span></div></article>
        <article className="metric-card"><div className="metric-icon blue">{icons.cube}</div><div><span>Dependencies</span><strong>{project.dependencies}</strong><p>{project.directDependencies} direct / {project.transitiveDependencies} transitive</p></div></article>
        <article className="metric-card"><div className="metric-icon slate">{icons.shield}</div><div><span>Vulnerabilities</span><strong>{project.vulnerabilities}</strong><p>From latest completed scan</p></div></article>
        <article className="metric-card"><div className="metric-icon sky">{icons.branch}</div><div><span>Reachable findings</span><strong>{project.reachable}</strong><p>{project.graphNodes ? `${project.graphNodes} graph nodes / ${project.graphEdges} edges` : 'Graph artifact not recorded'}</p></div></article>
      </section>
      <section className="panel portfolio-impact-panel">
        <div className="panel-header">
          <div><h2>Project vulnerability impact</h2><p>CVEs affecting this project in the latest completed scan</p></div>
          <span className="graph-scope-label">{projectFindings.length} findings</span>
        </div>
        <ImpactGraph mode="project" project={project} findings={projectFindings} selectedId={activeFinding.id} onSelect={(finding) => setActiveFindingId(finding.id)} />
      </section>
      <section className="content-grid">
        <div className="findings-panel panel">
          <div className="panel-header"><div><h2>Vulnerability findings</h2><p>Prioritized by reachability and exploit context</p></div><button className="text-button" onClick={() => window.location.assign('#/vulnerabilities')}>View all</button></div>
          <div className="filterbar"><div className="segmented">{['All', 'Reachable', 'Potentially'].map((item) => <button className={filter === item ? 'selected' : ''} key={item} onClick={() => setFilter(item)}>{item}</button>)}</div></div>
          <div className="finding-list">
            {visibleFindings.map((finding) => (
              <button className={`finding-row ${activeFinding.id === finding.id ? 'active' : ''}`} key={`${finding.id}-${finding.project}`} onClick={() => setActiveFindingId(finding.id)}>
                <span className={`severity-line ${finding.severity.toLowerCase()}`} />
                <span className="finding-main"><span className="finding-topline"><b>{finding.id}</b><SeverityBadge value={finding.severity} /><ReachabilityBadge value={finding.reachability} /></span><strong>{finding.title}</strong><span className="package-line"><code>{finding.package}</code><span>{finding.version}</span><span>CVSS {finding.score}</span></span></span>
                <span className="finding-meta">{finding.pathCount > 0 && <span>{icons.branch}{finding.pathCount} paths</span>}<small>{finding.published}</small></span><span className="row-arrow">&gt;</span>
              </button>
            ))}
          </div>
        </div>
        <aside className="activity-panel panel">
          <div className="panel-header compact"><div><h2>Scan health</h2><p>Latest persisted analysis data</p></div><span className="success-label">{project.latestScanStatus}</span></div>
          <div className="pipeline">
            {[
              ['Dependency resolution', `${project.dependencies} packages`, project.dependencies ? 'Recorded' : 'No data'],
              ['Vulnerability matching', `${project.vulnerabilities} findings`, project.latestScanStatus],
              ['Call graph analysis', project.graphNodes ? `${project.graphNodes} nodes / ${project.graphEdges} edges` : 'No artifact metadata', project.graphNodes ? 'Recorded' : 'Not recorded'],
              ['Affectedness assessment', `${project.reachable} reachable`, project.latestScanStatus],
            ].map(([label, result, state], index) => <div className="pipeline-step" key={label}><span className="step-check">✓</span><div><strong>{label}</strong><span>{result}</span></div><small>{state}</small>{index < 3 && <i />}</div>)}
          </div>
          <div className="scan-summary"><div><span>Total scan time</span><strong>{project.latestScanDuration || 'Not recorded'}</strong></div><div><span>Scan status</span><strong className="confidence-high">{project.latestScanStatus}</strong></div></div>
        </aside>
      </section>
      <section className="detail-panel panel">
        <div className="detail-header issue-header">
          <div>
            <div className="finding-topline"><SeverityBadge value={activeFinding.severity} /><ReachabilityBadge value={activeFinding.reachability} /><span className="confidence-tag">Engine verdict</span></div>
            <h2>{activeFinding.id}</h2>
            <strong>{activeFinding.title}</strong>
            <p>{activeFinding.summary}</p>
          </div>
          <dl className="issue-facts">
            <div><dt>Package</dt><dd>{activeFinding.package}@{activeFinding.version}</dd></div>
            <div><dt>Function</dt><dd>{activeFinding.functionName || 'Not localized'}</dd></div>
            <div><dt>Fix</dt><dd>{activeFinding.fixedVersion || 'Not available'}</dd></div>
          </dl>
        </div>
        <div className="detail-layout">
          <div className="graph-card">
            <div className="graph-toolbar"><div><h3>Reachable call path</h3><p>Persisted reachability path for this finding</p></div><div className="view-toggle">{(['Path', 'Code'] as const).map((mode) => <button className={graphMode === mode ? 'selected' : ''} key={mode} onClick={() => setGraphMode(mode)}>{mode}</button>)}</div></div>
            <PathSelector paths={paths} activeIndex={activePathIndex} onSelect={setActivePathIndex} />
            {graphMode === 'Path' ? (
              <CallPath path={activePath} fallbackTarget={activeFinding.functionName} graphNodes={project.graphNodes} graphEdges={project.graphEdges} status={pathStatus} />
            ) : <CodeEvidence path={activePath} />}
          </div>
          <aside className="evidence-card">
            <h3>Affectedness evidence</h3>
            <Evidence tone="success" icon="✓" title="Vulnerable version present">{activeFinding.package} {activeFinding.version} is inside the affected range.</Evidence>
            <Evidence tone="blue" icon=">" title="Function reachability">{activeFinding.pathCount} persisted path{activeFinding.pathCount === 1 ? '' : 's'} for this finding.</Evidence>
            <Evidence tone={activeFinding.evidenceStatus === 'complete' ? 'success' : activeFinding.evidenceStatus === 'partial' ? 'warning' : 'blue'} icon="i" title="Evidence status">{evidenceStatusText(activeFinding.evidenceStatus)}</Evidence>
            <div className="remediation"><span>Recommended fix</span><strong>Upgrade {activeFinding.package}</strong><div><code>{activeFinding.version}</code><span>-&gt;</span><code className="fixed">{activeFinding.fixedVersion}</code></div><button onClick={showInDevelopment}>View upgrade guidance <span>-&gt;</span></button></div>
          </aside>
        </div>
      </section>
    </>
  )
}

function ProjectHeading({ project, scanStatus, scanning, removing, onScan, onRemove }: { project: Project; scanStatus: string; scanning: boolean; removing: boolean; onScan: () => void; onRemove: () => void }) {
  return (
    <>
      <section className="project-heading">
        <div className="project-logo"><Icon size={27}><path d="M8.5 5.5 4 8v8l4.5 2.5M15.5 5.5 20 8v8l-4.5 2.5M8 12h8M12 8v8" /></Icon></div>
        <div className="project-title">
          <div className="eyebrow"><span className="status-dot" />Last scanned {project.lastScan}</div>
          <h1>{project.name}</h1>
          <p>{project.repository} <span>/</span> {project.branch} <span>/</span> {project.language}</p>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={showInDevelopment}>Export report</button>
          <button className="danger-button" disabled={removing} onClick={onRemove}>{removing ? 'Removing...' : 'Remove project'}</button>
          <button className="primary-button" disabled={scanning} onClick={onScan}>{icons.branch} {scanning ? 'Scanning...' : 'Scan again'}</button>
        </div>
      </section>
      {scanStatus && <section className="mini-activity"><span>{icons.clock}</span><p>{scanStatus}</p></section>}
    </>
  )
}

function ProjectEmptyState({ project, scanStatus, scanning, removing, onScan, onRemove }: { project: Project; scanStatus: string; scanning: boolean; removing: boolean; onScan: () => void; onRemove: () => void }) {
  return (
    <>
      <ProjectHeading project={project} scanStatus={scanStatus} scanning={scanning} removing={removing} onScan={onScan} onRemove={onRemove} />
      <section className="metric-grid">
        <article className="metric-card"><div className="metric-icon blue">{icons.cube}</div><div><span>Dependencies</span><strong>{project.dependencies}</strong><p>{project.directDependencies} direct / {project.transitiveDependencies} transitive</p></div></article>
        <article className="metric-card"><div className="metric-icon slate">{icons.shield}</div><div><span>Vulnerabilities</span><strong>{project.vulnerabilities}</strong><p>From latest completed scan</p></div></article>
        <article className="metric-card"><div className="metric-icon sky">{icons.branch}</div><div><span>Reachable findings</span><strong>{project.reachable}</strong><p>{project.latestScanStatus}</p></div></article>
      </section>
      <EmptyState title="No findings yet" description="Start a scan to resolve dependencies, query advisory data, build graph artifacts, and run reachability." />
    </>
  )
}

function Evidence({ tone, icon, title, children }: { tone: string; icon: string; title: string; children: ReactNode }) {
  return <div className="evidence-item"><span className={`evidence-icon ${tone}`}>{icon}</span><div><strong>{title}</strong><p>{children}</p></div></div>
}

function PathSelector({ paths, activeIndex, onSelect }: { paths: FindingPath[]; activeIndex: number; onSelect: (index: number) => void }) {
  if (paths.length <= 1) return null
  return (
    <div className="path-selector">
      <div className="path-selector-buttons">
        {paths.map((path, index) => (
          <button className={activeIndex === index ? 'selected' : ''} key={`${path.projectApi}-${index}`} onClick={() => onSelect(index)}>
            Path {index + 1}
          </button>
        ))}
      </div>
      <span>{paths[activeIndex]?.projectApi || paths[0]?.projectApi} to {paths[activeIndex]?.vulnerableTarget || paths[0]?.vulnerableTarget}</span>
    </div>
  )
}

function CallPath({ path, fallbackTarget, graphNodes, graphEdges, status }: { path?: FindingPath; fallbackTarget: string; graphNodes: number; graphEdges: number; status: string }) {
  const nodes = path?.path?.length ? path.path : [fallbackTarget].filter(Boolean)
  const evidenceByName = new Map((path?.nodes ?? []).map((node) => [node.name, node]))
  return (
    <div className="call-path">
      <div className="path-summary">
        <span>{nodes.length} step{nodes.length === 1 ? '' : 's'}</span>
        <strong>{status || `${graphNodes || 0} graph nodes / ${graphEdges || 0} edges`}</strong>
      </div>
      <ol className="path-evidence-list">
        {nodes.map((node, index) => (
          <PathStep
            key={`${node}-${index}`}
            index={index}
            name={node}
            evidence={evidenceByName.get(node)}
            vulnerableTarget={path?.vulnerableTarget || fallbackTarget}
          />
        ))}
      </ol>
      <div className="graph-legend">
        <span><i className="legend-app" />Application path</span>
        <span><i className="legend-package" />Package path</span>
        <span><i className="legend-vulnerable" />Vulnerable entity</span>
      </div>
    </div>
  )
}

function PathStep({ index, name, evidence, vulnerableTarget }: { index: number; name: string; evidence?: FindingPath['nodes'][number]; vulnerableTarget: string }) {
  const isVulnerableTarget = name === vulnerableTarget
  const kind = isVulnerableTarget ? 'vulnerable' : evidence?.kind || (index === 0 ? 'application' : 'package_internal')
  const hasEvidenceLine = Boolean(evidence && (evidence.file || evidence.callExpr || evidence.line))
  return (
    <li className={`path-step ${kind}`}>
      <span className="path-index">{index + 1}</span>
      <div>
        <span className="path-kind">{pathKindLabel(kind)}</span>
        <strong>{name}</strong>
        {hasEvidenceLine && evidence && (
          <small>
            {evidence.file && <code>{shortFile(evidence.file)}</code>}
            {Boolean(evidence.line) && <span>:{evidence.line}</span>}
            {evidence.callExpr && <em>{evidence.callExpr}</em>}
          </small>
        )}
      </div>
    </li>
  )
}

function CodeEvidence({ path }: { path?: FindingPath }) {
  const nodes = path?.nodes?.filter((node) => node.file || node.callExpr || node.line || node.sourceSnippet) ?? []
  if (!nodes.length) {
    return <div className="code-view"><div className="code-file"><span>Source evidence</span><b>Unavailable</b></div><pre><code>Source file and line evidence is not available for this path.</code></pre></div>
  }
  return (
    <div className="code-view">
      <div className="code-file"><span>Source evidence</span><b>{nodes.length} edge{nodes.length === 1 ? '' : 's'}</b></div>
      <div className="source-blocks">
        {nodes.map((node, index) => (
          <section className="source-block" key={`${node.name}-${index}`}>
            <header><span>{node.name}</span><code>{shortFile(node.file || 'unknown')}:{node.line || 0}</code></header>
            {node.callExpr && <p>{node.callExpr}</p>}
            <pre><code>{node.sourceSnippet || `${node.file || 'unknown'}:${node.line || 0}  ${node.name}  confidence=${node.confidence}`}</code></pre>
          </section>
        ))}
      </div>
      {!!path?.warnings?.length && <div className="path-warning-list">{path.warnings.slice(0, 3).map((warning, index) => {
        const item = warning as Record<string, unknown>
        return <span key={index}>{String(item.type || 'warning')}: {JSON.stringify(item.detail ?? item)}</span>
      })}</div>}
    </div>
  )
}

function riskLabelFor(score: number) {
  if (score >= 70) return 'High'
  if (score >= 40) return 'Medium'
  if (score > 0) return 'Low'
  return 'None'
}

function evidenceStatusText(status?: string) {
  if (status === 'complete') return 'File, line, and path evidence were persisted for this finding.'
  if (status === 'partial') return 'Reachability was persisted with partial evidence or analysis warnings.'
  return 'Evidence is unavailable because source or package summary data was incomplete.'
}

function pathKindLabel(kind: string) {
  if (kind === 'application') return 'Application'
  if (kind === 'package_api') return 'Package API'
  if (kind === 'vulnerable') return 'Vulnerable target'
  return 'Package internal'
}

function shortFile(file: string) {
  const normalized = file.replaceAll('\\', '/')
  const parts = normalized.split('/')
  return parts.slice(-2).join('/')
}
