import { icons } from '../components/icons'
import { MetricCard, PageHeader } from '../components/ui'
import type { ScanRecord } from '../types'

export function ScanActivityPage({ scans }: { scans: ScanRecord[] }) {
  const completed = scans.filter((scan) => scan.status === 'Completed').length
  const running = scans.filter((scan) => scan.status === 'Running' || scan.status === 'Queued').length
  const failed = scans.filter((scan) => scan.status === 'Failed').length

  return (
    <>
      <PageHeader eyebrow="Worker activity" title="Scan activity" description="Server-side scan jobs, worker status, and persisted finding counts." />
      <section className="metric-grid">
        <MetricCard icon={icons.clock} label="Recent scans" value={scans.length} detail="Latest server jobs" />
        <MetricCard icon={icons.branch} label="Active queue" value={running} detail="Queued or running" tone="navy" />
        <MetricCard icon={icons.shield} label="Completed" value={completed} detail="Finished successfully" tone="slate" />
        <MetricCard icon={icons.grid} label="Failed" value={failed} detail="Needs review" tone="sky" />
      </section>
      <section className="panel">
        <div className="table-toolbar"><div><h2>Scan jobs</h2><p>Loaded from Postgres scan_jobs and scan_findings</p></div></div>
        <div className="data-table scan-table">
          <div className="table-head"><span>Project</span><span>Trigger</span><span>Branch</span><span>Status</span><span>Duration</span><span>Findings</span><span>Date</span></div>
          {scans.map((scan, index) => (
            <div className="table-row" key={`${scan.project}-${scan.date}-${index}`}>
              <span className="entity-cell"><i className="project-avatar">{scan.project.slice(0, 2).toUpperCase()}</i><span><strong>{scan.project}</strong><small>{scan.trigger}</small></span></span>
              <span>{scan.trigger}</span>
              <span><code>{scan.branch || 'main'}</code></span>
              <span className={scan.status === 'Failed' ? 'vulnerability-count' : scan.status === 'Completed' ? 'reachable-count' : 'muted'}>{scan.status}</span>
              <span>{scan.duration || 'Running'}</span>
              <span>{scan.findings}</span>
              <span className="muted">{scan.date}</span>
            </div>
          ))}
          {!scans.length && <div className="table-row"><span className="muted">No scan jobs yet.</span></div>}
        </div>
      </section>
    </>
  )
}
