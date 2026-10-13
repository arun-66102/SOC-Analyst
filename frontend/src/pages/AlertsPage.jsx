import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getAlerts } from '../api'
import { Search, Filter, RefreshCw, ChevronRight, AlertTriangle } from 'lucide-react'

const SEVERITIES   = ['', 'Critical', 'High', 'Medium', 'Low']
const STATUSES     = ['', 'new', 'triaged', 'correlated', 'enriched', 'reported', 'escalated', 'dismissed', 'closed']
const CATEGORIES   = ['', 'BruteForce', 'DoS', 'DDoS', 'PortScan', 'Infiltration', 'WebAttack', 'Botnet', 'Malware', 'Exfiltration', 'Backdoor', 'Reconnaissance', 'Benign', 'Unknown']

function SeverityBadge({ sev }) {
  const map = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' }
  return <span className={`badge badge-${map[sev] || 'unknown'}`}>{sev || '—'}</span>
}

function TpBadge({ tp }) {
  if (tp === null || tp === undefined) return <span className="badge badge-unknown">—</span>
  return tp
    ? <span className="badge badge-green">True Positive</span>
    : <span className="badge" style={{ background: '#f1f5f9', color: '#475569', border: '1px solid #cbd5e1' }}>False Positive</span>
}

export default function AlertsPage() {
  const [alerts, setAlerts]           = useState([])
  const [total, setTotal]             = useState(0)
  const [loading, setLoading]         = useState(true)
  const [severity, setSeverity]       = useState('')
  const [status, setStatus]           = useState('')
  const [category, setCategory]       = useState('')
  const [page, setPage]               = useState(0)
  const limit = 20
  const navigate = useNavigate()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { limit, offset: page * limit }
      if (severity)  params.severity       = severity
      if (status)    params.status         = status
      if (category)  params.threat_category = category
      const { data } = await getAlerts(params)
      setAlerts(data.alerts || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [severity, status, category, page])

  useEffect(() => { load() }, [load])

  const totalPages = Math.ceil(total / limit)

  return (
    <div className="alerts-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Alerts</h1>
          <p className="page-subtitle">{total} alerts · Page {page + 1} of {Math.max(1, totalPages)}</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="filters-row card">
        <div className="filter-group">
          <Filter size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <select
            className="select"
            style={{ width: 130 }}
            value={severity}
            onChange={e => { setSeverity(e.target.value); setPage(0) }}
          >
            <option value="">All Severities</option>
            {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            className="select"
            style={{ width: 130 }}
            value={status}
            onChange={e => { setStatus(e.target.value); setPage(0) }}
          >
            <option value="">All Statuses</option>
            {STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            className="select"
            style={{ width: 150 }}
            value={category}
            onChange={e => { setCategory(e.target.value); setPage(0) }}
          >
            <option value="">All Categories</option>
            {CATEGORIES.filter(Boolean).map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
            <div className="spinner" style={{ width: 28, height: 28 }} />
          </div>
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Status</th>
                  <th>Result</th>
                  <th>MITRE</th>
                  <th>Timestamp</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr
                    key={a.event_id}
                    onClick={() => navigate(`/alerts/${a.event_id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td><SeverityBadge sev={a.severity} /></td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                        {a.threat_category || '—'}
                      </span>
                    </td>
                    <td><span className="mono">{a.src_ip || '—'}</span></td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.78rem' }}>
                        {a.dst_ip || '—'}:{a.dst_port || '—'}
                      </span>
                    </td>
                    <td><span className="mono">{a.protocol || '—'}</span></td>
                    <td><span className="badge badge-blue">{a.status}</span></td>
                    <td><TpBadge tp={a.is_true_positive} /></td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(a.mitre_techniques || []).slice(0, 2).map(t => (
                          <span key={t} className="badge badge-purple">{t}</span>
                        ))}
                        {(a.mitre_techniques || []).length > 2 && (
                          <span className="badge badge-unknown">+{a.mitre_techniques.length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td style={{ color: 'var(--text-dim)', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <ChevronRight size={14} style={{ color: 'var(--text-dim)' }} />
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={10}>
                      <div className="empty-state">
                        <AlertTriangle size={32} />
                        <p>No alerts match the current filters</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="pagination">
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={page === 0}
                  onClick={() => setPage(p => p - 1)}
                >← Prev</button>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  Page {page + 1} / {totalPages}
                </span>
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(p => p + 1)}
                >Next →</button>
              </div>
            )}
          </>
        )}
      </div>

      <style>{`
        .alerts-page { display: flex; flex-direction: column; gap: 16px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; }
        .page-title { font-size: 1.3rem; font-weight: 700; }
        .page-subtitle { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }
        .filters-row { display: flex; align-items: center; padding: 12px 16px; }
        .filter-group { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .pagination { display: flex; align-items: center; justify-content: center; gap: 16px; padding: 14px; border-top: 1px solid var(--border-subtle); }
      `}</style>
    </div>
  )
}
