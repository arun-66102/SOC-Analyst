/**
 * components/PageHeader.jsx
 * -------------------------
 * Reusable page header with title, subtitle, and optional action slot.
 *
 * Props:
 *   title    — string  page heading
 *   subtitle — string  (optional) short description line below title
 *   actions  — JSX     (optional) buttons / controls to show at right
 */

export default function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
      <div>
        <h1 style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 2 }}>
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>{actions}</div>}
    </div>
  )
}
