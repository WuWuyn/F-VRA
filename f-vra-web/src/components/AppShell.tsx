import { useState, type ReactNode } from 'react'
import { Icon } from './Icon'
import { icons } from './icons'
import { showInDevelopment } from '../lib/feedback'

const navigation = [
  { route: 'overview', label: 'Overview', icon: icons.grid },
  { route: 'projects', label: 'Projects', icon: icons.folder },
  { route: 'vulnerabilities', label: 'Vulnerabilities', icon: icons.shield },
  { route: 'graph', label: 'Graph Explorer', icon: icons.graph },
  { route: 'packages', label: 'Packages', icon: icons.cube },
  { route: 'activity', label: 'Scan activity', icon: icons.branch, development: true },
]

const manageNavigation = [
  { route: 'integrations', label: 'Integrations', icon: icons.plug, development: true },
  { route: 'settings', label: 'Settings', icon: icons.settings, development: true },
]

export function AppShell({ route, children }: { route: string; children: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const section = route === 'project' ? 'projects' : route
  const title = navigation.concat(manageNavigation).find((item) => item.route === section)?.label ?? (section === 'account' ? 'Account' : 'Overview')

  const navigate = (target: string) => {
    window.location.assign(`#/${target}`)
    setSidebarOpen(false)
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <img className="brand-logo" src="/f-vra-logo.svg" alt="F-VRA logo" />
          <strong>F-VRA</strong>
          <button className="sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">x</button>
        </div>
        <nav>
          <p className="nav-label">Product</p>
          {navigation.map((item) => (
            <button className={section === item.route ? 'active' : ''} key={item.route} onClick={() => navigate(item.route)}>
              {item.icon}
              <span>{item.label}</span>
              {item.development && <em className="nav-dev-badge">Dev</em>}
            </button>
          ))}
          <p className="nav-label nav-label-secondary">System</p>
          {manageNavigation.map((item) => (
            <button className={section === item.route ? 'active' : ''} key={item.route} onClick={() => navigate(item.route)}>
              {item.icon}
              <span>{item.label}</span>
              {item.development && <em className="nav-dev-badge">Dev</em>}
            </button>
          ))}
        </nav>
      </aside>
      {sidebarOpen && <button className="scrim" onClick={() => setSidebarOpen(false)} aria-label="Close navigation overlay" />}
      <main>
        <header className="topbar">
          <button className="menu-button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
            <Icon><path d="M4 7h16M4 12h16M4 17h16" /></Icon>
          </button>
          <div className="breadcrumb"><span>F-VRA</span><b>/</b><strong>{title}</strong></div>
          <div className="topbar-actions">
            <button className="icon-button" onClick={showInDevelopment} aria-label="Search">{icons.search}</button>
            <button className="icon-button notification" onClick={showInDevelopment} aria-label="Notifications">
              <Icon><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></Icon><span />
            </button>
            <button className="user-avatar-button" onClick={() => navigate('account')} aria-label="Account">
              <span className="user-avatar">FV</span>
            </button>
          </div>
        </header>
        <div className="page">{children}</div>
      </main>
    </div>
  )
}
