/**
 * components/SeverityBadge.jsx
 * ----------------------------
 * Reusable severity-level badge used across all dashboard pages.
 *
 * Props:
 *   sev  — "Critical" | "High" | "Medium" | "Low" | string | null
 */

export default function SeverityBadge({ sev }) {
  const map = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' }
  return (
    <span className={`badge badge-${map[sev] || 'unknown'}`}>
      {sev || '—'}
    </span>
  )
}
