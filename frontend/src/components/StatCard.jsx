/**
 * components/StatCard.jsx
 * -----------------------
 * Metric card used on the Overview dashboard.
 *
 * Props:
 *   label — string   display label
 *   value — string | number
 *   icon  — Lucide icon component
 *   color — CSS color string (e.g. '#dc2626')
 *   sub   — string   (optional) secondary text below value
 */

export default function StatCard({ label, value, icon: Icon, color, sub }) {
  return (
    <div
      className="card stat-card"
      style={{
        borderColor: `${color}30`,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: '16px 20px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>
          {label}
        </span>
        {Icon && (
          <div
            style={{
              width: 28, height: 28,
              background: `${color}18`,
              border: `1px solid ${color}30`,
              borderRadius: 8,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >
            <Icon size={14} color={color} />
          </div>
        )}
      </div>
      <div style={{ fontSize: '1.8rem', fontWeight: 800, color, lineHeight: 1, letterSpacing: '-0.02em' }}>
        {value ?? '—'}
      </div>
      {sub && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>{sub}</div>
      )}
    </div>
  )
}
