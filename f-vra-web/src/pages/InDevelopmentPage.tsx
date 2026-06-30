import { PageHeader } from '../components/ui'

export function InDevelopmentPage({ title }: { title: string }) {
  return (
    <section className="development-page">
      <PageHeader
        eyebrow="In development"
        title={title}
        description="This area is being simplified and wired into the product flow."
      />
      <div className="development-panel">
        <span>In development</span>
        <p>Core vulnerability analysis screens are available first. This section will be enabled after the underlying workflow is ready.</p>
      </div>
    </section>
  )
}
