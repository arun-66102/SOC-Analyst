/**
 * components/EmptyState.jsx
 * -------------------------
 * Reusable empty-state placeholder shown when a list has no data.
 *
 * Props:
 *   icon     — Lucide icon component to render
 *   title    — string  primary message
 *   subtitle — string  (optional) secondary message
 *   action   — JSX     (optional) action button / link
 */

export default function EmptyState({ icon: Icon, title, subtitle, action }) {
  return (
    <div className="empty-state card" style={{ padding: 64 }}>
      {Icon && <Icon size={40} style={{ opacity: 0.3 }} />}
      <p style={{ fontWeight: 600 }}>{title}</p>
      {subtitle && (
        <p style={{ fontSize: '0.82rem', color: 'var(--text-dim)' }}>{subtitle}</p>
      )}
      {action}
    </div>
  )
}
