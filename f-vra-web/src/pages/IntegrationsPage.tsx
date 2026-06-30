import { PageHeader } from '../components/ui'

const integrations = [
  { name: 'GitHub', description: 'Import repositories and scan every pull request.', state: 'Connected', initials: 'GH' },
  { name: 'GitLab', description: 'Synchronize projects and merge request findings.', state: 'Connect', initials: 'GL' },
  { name: 'Jira', description: 'Create remediation tickets from reachable findings.', state: 'Connected', initials: 'JI' },
  { name: 'Slack', description: 'Send risk alerts and scan summaries to channels.', state: 'Connect', initials: 'SL' },
  { name: 'Webhook', description: 'Stream scan events to your internal platform.', state: 'Configure', initials: 'WH' },
  { name: 'REST API', description: 'Query projects, findings, packages, and paths.', state: 'Configure', initials: 'API' },
]

export function IntegrationsPage() {
  return (
    <>
      <PageHeader eyebrow="Developer workflow" title="Integrations" description="Connect F-VRA to source control, issue tracking, messaging, and internal systems." />
      <section className="integration-grid">
        {integrations.map((item) => (
          <article className="integration-card panel" key={item.name}>
            <div className="integration-logo">{item.initials}</div>
            <div><h2>{item.name}</h2><p>{item.description}</p></div>
            <button className={item.state === 'Connected' ? 'connected-button' : 'secondary-button'}>{item.state === 'Connected' && <i />}{item.state}</button>
          </article>
        ))}
      </section>
      <section className="panel api-banner">
        <div><span className="page-eyebrow">Automation</span><h2>Build with the F-VRA API</h2><p>Integrate function-level vulnerability intelligence and call path evidence into your security platform.</p></div>
        <button className="primary-button">Open API documentation</button>
      </section>
    </>
  )
}

