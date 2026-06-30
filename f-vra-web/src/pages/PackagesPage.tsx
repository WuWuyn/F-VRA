import { useMemo, useState } from 'react'
import { icons } from '../components/icons'
import { MetricCard, PageHeader } from '../components/ui'
import { showInDevelopment } from '../lib/feedback'
import type { PackageRecord } from '../types'

export function PackagesPage({ packages }: { packages: PackageRecord[] }) {
  const [query, setQuery] = useState('')
  const visible = useMemo(() => packages.filter((item) => item.name.toLowerCase().includes(query.toLowerCase())), [packages, query])
  const direct = packages.filter((item) => item.direct).length
  const vulnerable = packages.filter((item) => item.vulnerabilities > 0).length

  return (
    <>
      <PageHeader eyebrow="Software bill of materials" title="Packages" description="Explore third-party components, dependency usage, licenses, and vulnerability exposure." actions={<button className="secondary-button" onClick={showInDevelopment}>Download SBOM</button>} />
      <section className="metric-grid">
        <MetricCard icon={icons.cube} label="Unique packages" value={packages.length} detail="Across all projects" />
        <MetricCard icon={icons.branch} label="Direct dependencies" value={direct} detail={`${packages.length - direct} transitive packages`} tone="navy" />
        <MetricCard icon={icons.shield} label="Vulnerable packages" value={vulnerable} detail="Reported by backend analysis" tone="slate" />
        <MetricCard icon={icons.grid} label="License data" value="Not analyzed" detail="License policy is not persisted yet" tone="sky" />
      </section>
      <section className="panel">
        <div className="table-toolbar"><div><h2>Package inventory</h2><p>Consolidated across connected projects</p></div><label className="search-field wide">{icons.search}<input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search packages" /></label></div>
        <div className="data-table package-table">
          <div className="table-head"><span>Package</span><span>Ecosystem</span><span>Relationship</span><span>Projects</span><span>Vulnerabilities</span><span>License</span></div>
          {visible.map((item) => (
            <div className="table-row" key={item.name}><span className="entity-cell"><i className="package-avatar">{item.name[0].toUpperCase()}</i><span><strong>{item.name}</strong><small>Version {item.version}</small></span></span><span className="ecosystem-tag">{item.ecosystem}</span><span>{item.direct ? 'Direct' : 'Transitive'}</span><span>{item.projects}</span><span className={item.vulnerabilities ? 'vulnerability-count' : 'muted'}>{item.vulnerabilities}</span><span><code>{item.license || 'Not analyzed'}</code></span></div>
          ))}
        </div>
      </section>
    </>
  )
}
