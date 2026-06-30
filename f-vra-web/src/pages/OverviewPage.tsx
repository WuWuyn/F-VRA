import { icons } from '../components/icons'
import { MetricCard, PageHeader, ReachabilityBadge, SeverityBadge } from '../components/ui'
import type { DashboardSummary, Finding, Severity } from '../types'

export function OverviewPage({ summary }: { summary: DashboardSummary }) {
  const { findings, projects, scans } = summary
  const reachable = findings.filter((item) => item.reachability === 'Reachable').length
  const highPriority = findings.filter((item) => item.severity === 'Critical' || item.severity === 'High').length
  const deprioritized = findings.filter((item) => item.reachability === 'Not reachable').length
  const noiseReduction = findings.length ? Math.round((deprioritized / findings.length) * 100) : 0
  const severityCounts = countSeverity(findings)

  return (
    <>
      <PageHeader eyebrow="Security posture" title="Overview" description="Reachability-aware risk across your Python application portfolio." actions={<button className="primary-button" onClick={() => window.location.assign('#/projects')}>{icons.plus} Add project</button>} />
      <section className="metric-grid">
        <MetricCard icon={icons.folder} label="Monitored projects" value={projects.length} detail="Loaded from the F-VRA API" />
        <MetricCard icon={icons.shield} label="Open vulnerabilities" value={findings.length} detail={`${highPriority} critical or high priority`} tone="navy" />
        <MetricCard icon={icons.branch} label="Reachable findings" value={reachable} detail="Confirmed or production-relevant paths" tone="slate" />
        <MetricCard icon={icons.trend} label="Noise reduction" value={`${noiseReduction}%`} detail={`${deprioritized} findings deprioritized`} tone="sky" />
      </section>
      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-header"><div><h2>Highest risk projects</h2><p>Prioritized by reachable vulnerabilities</p></div><button className="text-button" onClick={() => window.location.assign('#/projects')}>View projects</button></div>
          <div className="project-summary-list">
            {[...projects].sort((a, b) => b.riskScore - a.riskScore).slice(0, 4).map((project) => (
              <button key={project.id} onClick={() => window.location.assign(`#/project/${project.id}`)}>
                <span className="project-avatar">{project.name.slice(0, 2).toUpperCase()}</span>
                <span><strong>{project.name}</strong><small>{project.repository}</small></span>
                <span className="summary-number"><strong>{project.reachable}</strong><small>reachable</small></span>
                <span className={`risk-score score-${project.riskScore >= 75 ? 'high' : project.riskScore >= 50 ? 'medium' : 'low'}`}>{project.riskScore}</span>
              </button>
            ))}
          </div>
        </article>
        <article className="panel">
          <div className="panel-header"><div><h2>Risk distribution</h2><p>Current affectedness assessment</p></div></div>
          <div className="risk-distribution">
            <div className="donut"><div><strong>{findings.length}</strong><span>findings</span></div></div>
            <div className="distribution-legend">
              <span><i className="critical-dot" />Critical <b>{severityCounts.Critical}</b></span>
              <span><i className="high-dot" />High <b>{severityCounts.High}</b></span>
              <span><i className="medium-dot" />Medium <b>{severityCounts.Medium}</b></span>
              <span><i className="low-dot" />Low <b>{severityCounts.Low}</b></span>
            </div>
          </div>
        </article>
      </section>
      <section className="panel overview-findings">
        <div className="panel-header"><div><h2>Priority findings</h2><p>Reachable issues requiring action</p></div><button className="text-button" onClick={() => window.location.assign('#/vulnerabilities')}>View all</button></div>
        <div className="compact-table">
          {findings.filter((item) => item.reachability === 'Reachable').map((finding) => (
            <div className="compact-row" key={`${finding.id}-${finding.project}`}>
              <span><strong>{finding.id}</strong><small>{finding.title}</small></span>
              <span><code>{finding.package}@{finding.version}</code></span>
              <SeverityBadge value={finding.severity} />
              <ReachabilityBadge value={finding.reachability} />
              <span className="muted">{finding.project}</span>
            </div>
          ))}
        </div>
      </section>
      {scans[0] && (
        <section className="mini-activity">
          <span>{icons.clock}</span><p>Latest scan: <strong>{scans[0].project}</strong> completed {scans[0].date} with {scans[0].findings} findings.</p>
        </section>
      )}
    </>
  )
}

function countSeverity(findings: Finding[]) {
  return findings.reduce<Record<Severity, number>>((counts, finding) => {
    counts[finding.severity] += 1
    return counts
  }, { Critical: 0, High: 0, Medium: 0, Low: 0 })
}
