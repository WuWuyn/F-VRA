import { PortfolioGraph } from '../components/PortfolioGraph'
import { PageHeader } from '../components/ui'
import type { Finding, Project } from '../types'

export function GraphExplorerPage({ findings, projects }: { findings: Finding[]; projects: Project[] }) {
  return (
    <div className="graph-explorer-page">
      <PageHeader eyebrow="Portfolio visualization" title="Graph Explorer" description="Explore all projects, vulnerable dependencies, and CVEs in one interactive graph." />
      <PortfolioGraph findings={findings} projects={projects} />
    </div>
  )
}
