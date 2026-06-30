import { useMemo, useState } from 'react'
import { ImpactGraph } from '../components/ImpactGraph'
import { icons } from '../components/icons'
import { EmptyState, MetricCard, PageHeader, ReachabilityBadge, SeverityBadge } from '../components/ui'
import { showInDevelopment } from '../lib/feedback'
import type { Finding, Project } from '../types'

export function VulnerabilitiesPage({ findings, projects }: { findings: Finding[]; projects: Project[] }) {
  const [filter, setFilter] = useState('All')
  const [query, setQuery] = useState('')
  const [selectedCve, setSelectedCve] = useState(findings[0]?.id ?? '')
  const activeCve = findings.some((finding) => finding.id === selectedCve) ? selectedCve : findings[0]?.id ?? ''

  const visible = useMemo(() => findings.filter((item) => (filter === 'All' || item.reachability.startsWith(filter)) && `${item.id} ${item.package} ${item.title}`.toLowerCase().includes(query.toLowerCase())), [filter, findings, query])
  const selectedFinding = findings.find((item) => item.id === activeCve) ?? findings[0]
  const affectedProjects = selectedFinding ? findings.filter((item) => item.id === selectedFinding.id) : []
  const reachable = findings.filter((item) => item.reachability === 'Reachable').length
  const potential = findings.filter((item) => item.reachability === 'Potentially reachable').length
  const notReachable = findings.filter((item) => item.reachability === 'Not reachable').length

  return (
    <>
      <PageHeader eyebrow="Affectedness intelligence" title="Vulnerabilities" description="Prioritize CVEs using function-level reachability, execution context, and evidence confidence." actions={<button className="secondary-button" onClick={showInDevelopment}>Export findings</button>} />
      <section className="metric-grid">
        <MetricCard icon={icons.shield} label="Open findings" value={findings.length} detail={`Across ${projects.length} monitored projects`} />
        <MetricCard icon={icons.branch} label="Reachable" value={reachable} detail="Confirmed production paths" tone="navy" />
        <MetricCard icon={icons.trend} label="Potentially reachable" value={potential} detail="Needs manual review" tone="slate" />
        <MetricCard icon={icons.grid} label="Not reachable" value={notReachable} detail="Deprioritized with evidence" tone="sky" />
      </section>
      {selectedFinding ? (
        <section className="panel portfolio-impact-panel">
          <div className="panel-header">
            <div><h2>CVE portfolio impact</h2><p>Select a finding below to see every affected project and its reachability status</p></div>
            <span className="graph-scope-label">{affectedProjects.length} projects</span>
          </div>
          <ImpactGraph
            mode="cve"
            finding={selectedFinding}
            affectedFindings={affectedProjects}
            projects={projects}
            onSelectProject={(projectId) => window.location.assign(`#/project/${projectId}`)}
          />
        </section>
      ) : <EmptyState title="No vulnerabilities" description="The API did not return any vulnerability findings." />}
      <section className="panel">
        <div className="table-toolbar">
          <div className="segmented">{['All', 'Reachable', 'Potentially'].map((item) => <button className={filter === item ? 'selected' : ''} key={item} onClick={() => setFilter(item)}>{item}</button>)}</div>
          <label className="search-field wide">{icons.search}<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE or package" /></label>
        </div>
        <div className="data-table vulnerability-table">
          <div className="table-head"><span>Finding</span><span>Package</span><span>Severity</span><span>Reachability</span><span>Project</span><span>Fix version</span></div>
          {visible.map((finding) => (
            <button className={`table-row ${activeCve === finding.id ? 'selected-row' : ''}`} key={`${finding.id}-${finding.project}`} onClick={() => setSelectedCve(finding.id)}>
              <span className="entity-cell"><span><strong className="link-text">{finding.id}</strong><small>{finding.title}</small></span></span>
              <span><code>{finding.package}@{finding.version}</code></span><SeverityBadge value={finding.severity} /><ReachabilityBadge value={finding.reachability} /><span>{finding.project}</span><span><code className="fixed-version">{finding.fixedVersion}</code></span>
            </button>
          ))}
        </div>
      </section>
    </>
  )
}
