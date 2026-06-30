import type { ReactNode } from 'react'
import type { Reachability, Severity } from '../types'

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: ReactNode }) {
  return (
    <section className="page-heading">
      <div>
        {eyebrow && <span className="page-eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="heading-actions">{actions}</div>}
    </section>
  )
}

export function MetricCard({ icon, label, value, detail, tone = 'blue' }: { icon: ReactNode; label: string; value: string | number; detail: string; tone?: string }) {
  return (
    <article className="metric-card">
      <div className={`metric-icon ${tone}`}>{icon}</div>
      <div><span>{label}</span><strong>{value}</strong><p>{detail}</p></div>
    </article>
  )
}

export function SeverityBadge({ value }: { value: Severity }) {
  return <span className={`severity-pill ${value.toLowerCase()}`}>{value}</span>
}

export function ReachabilityBadge({ value }: { value: Reachability }) {
  return <span className={`reachability-pill ${value.toLowerCase().replaceAll(' ', '-')}`}><i />{value}</span>
}

export function RiskBadge({ score }: { score: number }) {
  const level = score >= 75 ? 'high' : score >= 50 ? 'medium' : 'low'
  return <span className={`risk-badge ${level}`}>{score} · {level}</span>
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return <div className="empty-state"><strong>{title}</strong><span>{description}</span></div>
}
