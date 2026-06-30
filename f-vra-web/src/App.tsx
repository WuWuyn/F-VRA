import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { AppShell } from './components/AppShell'
import { getDashboardSummary } from './lib/api'
import { IN_DEVELOPMENT_EVENT } from './lib/feedback'
import { GraphExplorerPage } from './pages/GraphExplorerPage'
import { InDevelopmentPage } from './pages/InDevelopmentPage'
import { OverviewPage } from './pages/OverviewPage'
import { PackagesPage } from './pages/PackagesPage'
import { ProjectDetailPage } from './pages/ProjectDetailPage'
import { ProjectsPage } from './pages/ProjectsPage'
import { ScanActivityPage } from './pages/ScanActivityPage'
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage'
import type { DashboardSummary } from './types'
import './App.css'

const developmentPages: Record<string, string> = {
  account: 'Account',
  integrations: 'Integrations',
  settings: 'Settings',
}

function getRoute() {
  const path = window.location.hash.replace(/^#\//, '') || 'overview'
  const [route, id] = path.split('/')
  return { route, id }
}

function App() {
  const [location, setLocation] = useState(getRoute)
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [dataError, setDataError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const onHashChange = () => setLocation(getRoute())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  useEffect(() => {
    const onDevelopment = (event: Event) => {
      setNotice(event instanceof CustomEvent && event.detail ? String(event.detail) : 'In development')
    }
    window.addEventListener(IN_DEVELOPMENT_EVENT, onDevelopment)
    return () => window.removeEventListener(IN_DEVELOPMENT_EVENT, onDevelopment)
  }, [])

  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(''), 2200)
    return () => window.clearTimeout(timer)
  }, [notice])

  useEffect(() => {
    getDashboardSummary()
      .then((data) => {
        setSummary(data)
        setDataError('')
      })
      .catch(() => setDataError('Unable to load F-VRA data from the API.'))
  }, [])

  const refreshSummary = () => {
    return getDashboardSummary()
      .then((data) => {
        setSummary(data)
        setDataError('')
      })
      .catch(() => setDataError('Unable to load F-VRA data from the API.'))
  }

  if (dataError) {
    return (
      <AppShell route={location.route}>
        <StatusPanel title="Connection problem" message={dataError} actionLabel="Retry" onAction={() => getDashboardSummary().then(setSummary)} />
      </AppShell>
    )
  }

  if (!summary) {
    return (
      <AppShell route={location.route}>
        <StatusPanel title="Loading analysis data" message="Fetching projects, vulnerabilities, packages, and graph evidence from the API." />
      </AppShell>
    )
  }

  const pages: Record<string, ReactNode> = {
    overview: <OverviewPage summary={summary} />,
    projects: <ProjectsPage projects={summary.projects} onChanged={refreshSummary} />,
    vulnerabilities: <VulnerabilitiesPage findings={summary.findings} projects={summary.projects} />,
    graph: <GraphExplorerPage findings={summary.findings} projects={summary.projects} />,
    packages: <PackagesPage packages={summary.packages} />,
    activity: <ScanActivityPage scans={summary.scans} />,
  }

  const content = location.route === 'project'
    ? <ProjectDetailPage projectId={location.id || summary.projects[0]?.id || ''} projects={summary.projects} findings={summary.findings} onChanged={refreshSummary} />
    : developmentPages[location.route]
      ? <InDevelopmentPage title={developmentPages[location.route]} />
      : pages[location.route] ?? <OverviewPage summary={summary} />

  return (
    <AppShell route={location.route}>
      {content}
      {notice && <div className="app-toast" role="status">{notice}</div>}
    </AppShell>
  )
}

function StatusPanel({ title, message, actionLabel, onAction }: { title: string; message: string; actionLabel?: string; onAction?: () => void }) {
  return (
    <section className="development-page">
      <div className="development-panel">
        <span>{title}</span>
        <p>{message}</p>
        {actionLabel && <button className="primary-button" onClick={onAction}>{actionLabel}</button>}
      </div>
    </section>
  )
}

export default App
