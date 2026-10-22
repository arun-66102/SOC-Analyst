import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { getIncidents, getAlerts } from '../api'
import { GitBranch, Clock, Shield, AlertTriangle, ChevronRight, RefreshCw } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'

function SevBar({ events }) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 }
  events.forEach(e => {
    const s = e.severity || 'Unknown'
    counts[s] = (counts[s] || 0) + 1
  })
  const total = events.length || 1
  const colors = { Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)', Unknown: 'var(--unknown)' }
  return (
    <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1, marginTop: 6 }}>
      {Object.entries(counts).filter(([,v]) => v > 0).map(([k, v]) => (
        <div key={k} style={{ flex: v / total, background: colors[k], minWidth: 3 }} title={`${k}: ${v}`} />
      ))}
    </div>
  )
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [alerts, setAlerts]       = useState([])
  const [loading, setLoading]     = useState(true)
  const navigate = useNavigate()

  const load = async () => {
    setLoading(true)
    try {
      const [iR, aR] = await Promise.allSettled([getIncidents(), getAlerts({ limit: 500 })])
      if (iR.status === 'fulfilled') setIncidents(iR.value.data || [])
      if (aR.status === 'fulfilled') setAlerts(aR.value.data.alerts || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Group alerts by incident
  const alertsByIncident = {}
  alerts.forEach(a => {
    if (a.incident_id) {
      if (!alertsByIncident[a.incident_id]) alertsByIncident[a.incident_id] = []
      alertsByIncident[a.incident_id].push(a)
    }
  })

  return (
    <div className="incidents-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Correlated Incidents</h1>
          <p className="page-subtitle">{incidents.length} incidents · AI-grouped security event clusters</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
          <div className="spinner" style={{ width: 28, height: 28 }} />
        </div>
      ) : incidents.length === 0 ? (
        <div className="empty-state card" style={{ padding: 64 }}>
          <GitBranch size={40} style={{ opacity: 0.3 }} />
          <p>No incidents found. Run the pipeline on some events to create incidents.</p>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/analyze')}>
            Analyze Events
          </button>
        </div>
      ) : (
        <div className="incidents-grid">
          {incidents.map(inc => {
            const relatedAlerts = alertsByIncident[inc.incident_id] || []
            const duration = inc.end_time
              ? Math.round((new Date(inc.end_time) - new Date(inc.start_time)) / 60000)
              : 0
            return (
              <div key={inc.incident_id} className="card incident-card">
                {/* Header */}
                <div className="inc-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <GitBranch size={14} style={{ color: 'var(--accent-purple)' }} />
                    <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--accent-cyan)' }}>
                      {inc.incident_id.slice(0, 16)}…
                    </span>
                  </div>
                  <SeverityBadge sev={inc.severity} />
                </div>

                {/* Stats */}
                <div className="inc-stats">
                  <div className="inc-stat">
                    <AlertTriangle size={12} style={{ color: 'var(--high)' }} />
                    <span>{inc.event_count} events</span>
                  </div>
                  <div className="inc-stat">
                    <Clock size={12} style={{ color: 'var(--text-muted)' }} />
                    <span>{duration > 0 ? `${duration}m duration` : 'Ongoing'}</span>
                  </div>
                  <div className="inc-stat">
                    <Shield size={12} style={{ color: 'var(--accent-purple)' }} />
                    <span>{inc.mitre_techniques.length} techniques</span>
                  </div>
                </div>

                {/* Severity bar */}
                {relatedAlerts.length > 0 && <SevBar events={relatedAlerts} />}

                {/* MITRE tags */}
                {inc.mitre_techniques.length > 0 && (
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 10 }}>
                    {inc.mitre_techniques.map(t => (
                      <span key={t} className="badge badge-purple">{t}</span>
                    ))}
                  </div>
                )}

                {/* Timeline */}
                <div className="inc-timeline">
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>
                    Started: {new Date(inc.start_time).toLocaleString()}
                  </span>
                  {inc.end_time && (
                    <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>
                      Ended: {new Date(inc.end_time).toLocaleString()}
                    </span>
                  )}
                </div>

                {/* Status + Action */}
                <div className="inc-footer">
                  <span className="badge badge-blue">{inc.status}</span>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => navigate(`/reports?incident=${inc.incident_id}`)}
                  >
                    View Report <ChevronRight size={12} />
                  </button>
                </div>

                {/* Related alerts preview */}
                {relatedAlerts.length > 0 && (
                  <div className="inc-alerts">
                    <p className="section-title">Related Alerts</p>
                    {relatedAlerts.slice(0, 3).map(a => (
                      <div key={a.event_id} className="inc-alert-row" onClick={() => navigate(`/alerts/${a.event_id}`)}>
                        <SeverityBadge sev={a.severity} />
                        <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', flex: 1 }}>
                          {a.threat_category}
                        </span>
                        <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {a.src_ip || '—'}
                        </span>
                        <ChevronRight size={11} style={{ color: 'var(--text-dim)' }} />
                      </div>
                    ))}
                    {relatedAlerts.length > 3 && (
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', paddingTop: 4 }}>
                        +{relatedAlerts.length - 3} more
                      </p>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      <style>{`
        .incidents-page { display: flex; flex-direction: column; gap: 16px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; }
        .page-title { font-size: 1.3rem; font-weight: 700; }
        .page-subtitle { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }

        .incidents-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
          gap: 16px;
        }
        .incident-card { display: flex; flex-direction: column; gap: 10px; }
        .inc-header { display: flex; align-items: center; justify-content: space-between; }
        .inc-stats { display: flex; gap: 16px; flex-wrap: wrap; }
        .inc-stat { display: flex; align-items: center; gap: 4px; font-size: 0.78rem; color: var(--text-muted); }
        .inc-timeline { display: flex; flex-direction: column; gap: 2px; padding-top: 4px; }
        .inc-footer { display: flex; align-items: center; justify-content: space-between; padding-top: 4px; border-top: 1px solid var(--border-subtle); }
        .inc-alerts { padding-top: 8px; border-top: 1px solid var(--border-subtle); display: flex; flex-direction: column; gap: 6px; }
        .inc-alert-row {
          display: flex; align-items: center; gap: 8px;
          padding: 6px 8px;
          background: var(--bg-elevated);
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.15s;
        }
        .inc-alert-row:hover { background: var(--bg-card); }
      `}</style>
    </div>
  )
}
