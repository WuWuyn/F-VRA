import { useState } from 'react'
import { PageHeader } from '../components/ui'

function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return <button className={`toggle ${checked ? 'on' : ''}`} onClick={onChange} aria-pressed={checked}><span /></button>
}

export function SettingsPage() {
  const [reachability, setReachability] = useState(true)
  const [testPaths, setTestPaths] = useState(false)
  const [notifications, setNotifications] = useState(true)
  return (
    <>
      <PageHeader eyebrow="Workspace administration" title="Settings" description="Configure analysis behavior, risk policies, notifications, and workspace access." actions={<button className="primary-button">Save changes</button>} />
      <div className="settings-layout">
        <aside className="settings-nav panel"><button className="active">General</button><button>Analysis</button><button>Risk policy</button><button>Notifications</button><button>Team members</button><button>Billing</button></aside>
        <div className="settings-content">
          <section className="panel settings-section">
            <div className="settings-heading"><h2>Workspace details</h2><p>Basic information shown throughout F-VRA.</p></div>
            <div className="form-grid"><label><span>Workspace name</span><input defaultValue="Acme Security" /></label><label><span>Workspace slug</span><input defaultValue="acme-security" /></label><label className="full"><span>Default branch</span><input defaultValue="main" /></label></div>
          </section>
          <section className="panel settings-section">
            <div className="settings-heading"><h2>Analysis defaults</h2><p>Applied to new projects unless overridden.</p></div>
            <div className="setting-row"><div><strong>Function-level reachability</strong><p>Build call graphs and validate paths to vulnerable entities.</p></div><Toggle checked={reachability} onChange={() => setReachability(!reachability)} /></div>
            <div className="setting-row"><div><strong>Include test-only paths</strong><p>Report vulnerable functions reachable exclusively from tests.</p></div><Toggle checked={testPaths} onChange={() => setTestPaths(!testPaths)} /></div>
            <div className="setting-row"><div><strong>Critical finding alerts</strong><p>Notify workspace administrators when a critical reachable CVE appears.</p></div><Toggle checked={notifications} onChange={() => setNotifications(!notifications)} /></div>
          </section>
        </div>
      </div>
    </>
  )
}
