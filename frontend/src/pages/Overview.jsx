import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, LineChart, Line, CartesianGrid, Legend
} from 'recharts'
import { getStats, getAlerts, getIncidents } from '../api'
import {
  AlertTriangle, Shield, GitBranch, TrendingUp,
  RefreshCw, ChevronRight, Clock, CheckCircle, XCircle
} from 'lucide-react'

const SEV_COLORS = {
  Critical: '#dc2626',
  High:     '#ea580c',
  Medium:   '#d97706',
  Low:      '#16a34a',
  Unknown:  '#64748b',
}

const REFRESH_INTERVAL = 10000 // 10 seconds

function StatCard({ label, value, icon: Icon, color, sub }) {
  return (
    <div className="stat-card" style={{ borderColor: `${color}30` }}>
      <div className="stat-header">
        <span className="stat-label">{label}</span>
        <div className="stat-icon" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
          <Icon size={14} color={color} />
        </div>
      </div>
      <div className="stat-value" style={{ color }}>{value ?? '—'}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

function SeverityBadge({ sev }) {
  const map = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low' }
  return <span className={`badge badge-${map[sev] || 'unknown'}`}>{sev}</span>
}

export default function Overview() {
  const [stats, setStats]   = useState(null)
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState(null)
  const navigate = useNavigate()

  const refresh = useCallback(async () => {
    try {
      const [sR, aR, iR] = await Promise.allSettled([
        getStats(), getAlerts({ limit: 10 }), getIncidents()
      ])
      if (sR.status === 'fulfilled') setStats(sR.value.data)
      if (aR.status === 'fulfilled') setAlerts(aR.value.data.alerts || [])
      if (iR.status === 'fulfilled') setIncidents(iR.value.data || [])
      setLastRefresh(new Date())
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, REFRESH_INTERVAL)
    return () => clearInterval(t)
  }, [refresh])

  // Pie data
  const pieData = stats ? [
    { name: 'Critical', value: stats.critical_count },
    { name: 'High',     value: stats.high_count },
    { name: 'Medium',   value: stats.medium_count },
    { name: 'Low',      value: stats.low_count },
  ].filter(d => d.value > 0) : []

  // MITRE bar data
  const mitreData = (stats?.top_mitre_techniques || []).map(t => ({
    id:    t.technique_id,
    count: t.count,
  }))

  // Timeline data from alerts (last 24h simulation)
  const timelineData = (() => {
    const buckets = {}
    alerts.forEach(a => {
      const h = new Date(a.timestamp).getHours()
      const key = `${h.toString().padStart(2,'0')}:00`
      buckets[key] = (buckets[key] || 0) + 1
    })
    return Object.entries(buckets).sort().map(([t, v]) => ({ time: t, alerts: v }))
  })()

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null
    return (
      <div className="chart-tooltip">
        <p className="chart-tooltip-label">{label}</p>
        {payload.map((p, i) => (
          <p key={i} style={{ color: p.color || p.fill }}>
            {p.name}: <strong>{p.value}</strong>
          </p>
        ))}
      </div>
    )
  }

  if (loading) {
    return (
      <div className="loading-center">
        <div className="spinner" style={{ width: 32, height: 32 }} />
        <p style={{ color: 'var(--text-muted)', marginTop: 12 }}>Loading dashboard…</p>
      </div>
    )
  }

  return (
    <div className="overview-page fade-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Operations Center</h1>
          <p className="page-subtitle">
            Real-time AI-powered threat intelligence dashboard
          </p>
        </div>
        <div className="header-actions">
          {lastRefresh && (
            <span className="last-refresh">
              <Clock size={12} /> {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button className="btn btn-ghost btn-sm" onClick={refresh}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        <StatCard
          label="Total Alerts"
          value={stats?.total_alerts ?? 0}
          icon={AlertTriangle}
          color="var(--accent-cyan)"
          sub={`${stats?.true_positives ?? 0} true positives`}
        />
        <StatCard
          label="Critical"
          value={stats?.critical_count ?? 0}
          icon={AlertTriangle}
          color="var(--critical)"
          sub="Immediate action required"
        />
        <StatCard
          label="Active Incidents"
          value={stats?.active_incidents ?? 0}
          icon={GitBranch}
          color="var(--accent-purple)"
          sub="Correlated event groups"
        />
        <StatCard
          label="Avg Triage Latency"
          value={stats?.avg_triage_latency_ms ? `${stats.avg_triage_latency_ms}ms` : '—'}
          icon={TrendingUp}
          color="var(--accent-green)"
          sub="Per event"
        />
      </div>

      {/* Charts row */}
      <div className="charts-row">
        {/* Severity Pie */}
        <div className="card chart-card">
          <h3 className="chart-title">Severity Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map(entry => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  formatter={(val) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 32 }}>
              <p>No alert data</p>
            </div>
          )}
        </div>

        {/* MITRE Bar */}
        <div className="card chart-card">
          <h3 className="chart-title">Top MITRE ATT&CK Techniques</h3>
          {mitreData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={mitreData} layout="vertical" margin={{ left: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} />
                <YAxis type="category" dataKey="id" width={65} tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'JetBrains Mono' }} axisLine={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,212,255,0.06)' }} />
                <Bar dataKey="count" fill="var(--accent-blue)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 32 }}>
              <p>No MITRE data yet</p>
            </div>
          )}
        </div>

        {/* Alert Timeline */}
        <div className="card chart-card chart-card-wide">
          <h3 className="chart-title">Alert Volume (Today)</h3>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
                <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Line type="monotone" dataKey="alerts" stroke="var(--accent-cyan)" strokeWidth={2} dot={{ fill: 'var(--accent-cyan)', r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: 32 }}>
              <p>No timeline data</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Alerts & Incidents */}
      <div className="bottom-row">
        {/* Recent Alerts */}
        <div className="card bottom-card">
          <div className="card-header">
            <h3 className="chart-title" style={{ margin: 0 }}>Recent Alerts</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')}>
              View all <ChevronRight size={12} />
            </button>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Source IP</th>
                <th>Status</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 8).map(a => (
                <tr key={a.event_id} className="table-row-link" onClick={() => navigate(`/alerts/${a.event_id}`)}>
                  <td><SeverityBadge sev={a.severity} /></td>
                  <td><span className="mono" style={{ color: 'var(--text-secondary)' }}>{a.threat_category}</span></td>
                  <td><span className="mono">{a.src_ip || '—'}</span></td>
                  <td>
                    <span className="badge badge-blue">{a.status}</span>
                  </td>
                  <td style={{ color: 'var(--text-dim)', fontSize: '0.78rem' }}>
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-dim)', padding: 24 }}>No alerts yet</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Active Incidents */}
        <div className="card bottom-card bottom-card-sm">
          <div className="card-header">
            <h3 className="chart-title" style={{ margin: 0 }}>Active Incidents</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/incidents')}>
              View all <ChevronRight size={12} />
            </button>
          </div>
          <div className="incident-list">
            {incidents.slice(0, 6).map(inc => (
              <div key={inc.incident_id} className="incident-item" onClick={() => navigate('/incidents')}>
                <div className="incident-item-header">
                  <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                    {inc.incident_id.slice(0, 12)}…
                  </span>
                  <SeverityBadge sev={inc.severity} />
                </div>
                <div className="incident-item-meta">
                  <span>{inc.event_count} events</span>
                  <span>{new Date(inc.start_time).toLocaleDateString()}</span>
                </div>
                {inc.mitre_techniques.length > 0 && (
                  <div style={{ marginTop: 4, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {inc.mitre_techniques.slice(0,3).map(t => (
                      <span key={t} className="badge badge-purple">{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {incidents.length === 0 && (
              <div className="empty-state" style={{ padding: 24 }}>
                <p>No incidents found</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        .overview-page { display: flex; flex-direction: column; gap: 20px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 12px; }
        .page-title { font-size: 1.4rem; font-weight: 700; color: var(--text-primary); }
        .page-subtitle { font-size: 0.85rem; color: var(--text-muted); margin-top: 2px; }
        .header-actions { display: flex; align-items: center; gap: 12px; }
        .last-refresh { display: flex; align-items: center; gap: 4px; font-size: 0.75rem; color: var(--text-dim); }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
        }
        .stat-card {
          background: var(--bg-card);
          border: 1px solid var(--border-subtle);
          border-radius: 12px;
          padding: 18px;
          box-shadow: var(--shadow-sm);
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .stat-card:hover { border-color: var(--border-glow); box-shadow: var(--shadow-md); }
        .stat-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
        .stat-label { font-size: 0.72rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }
        .stat-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; }
        .stat-value { font-size: 1.9rem; font-weight: 800; line-height: 1; }
        .stat-sub { font-size: 0.72rem; color: var(--text-dim); margin-top: 4px; }

        .charts-row {
          display: grid;
          grid-template-columns: 240px 1fr 1fr;
          gap: 16px;
        }
        .chart-card { min-height: 250px; }
        .chart-card-wide { grid-column: span 1; }
        .chart-title { font-size: 0.78rem; font-weight: 700; color: var(--text-secondary); margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.06em; }
        .chart-tooltip {
          background: #ffffff;
          border: 1px solid var(--border-subtle);
          box-shadow: var(--shadow-md);
          border-radius: 8px;
          padding: 8px 12px;
          font-size: 0.8rem;
          color: var(--text-primary);
        }
        .chart-tooltip-label { color: var(--text-muted); font-size: 0.72rem; margin-bottom: 4px; font-weight: 600; }

        .bottom-row {
          display: grid;
          grid-template-columns: 1fr 340px;
          gap: 16px;
        }
        .bottom-card { overflow-x: auto; }
        .card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
        .table-row-link { cursor: pointer; }
        .table-row-link:hover td { background: #f8fafc !important; }

        .incident-list { display: flex; flex-direction: column; gap: 10px; }
        .incident-item {
          background: #ffffff;
          border: 1px solid var(--border-subtle);
          border-radius: 8px;
          padding: 12px;
          cursor: pointer;
          box-shadow: 0 1px 2px rgba(15,23,42,0.03);
          transition: border-color 0.15s, box-shadow 0.15s;
        }
        .incident-item:hover { border-color: var(--border-glow); box-shadow: var(--shadow-sm); }
        .incident-item-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
        .incident-item-meta { display: flex; gap: 16px; font-size: 0.72rem; color: var(--text-dim); }

        .loading-center { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 60vh; gap: 12px; }

        @media (max-width: 1024px) {
          .stats-grid { grid-template-columns: repeat(2, 1fr); }
          .charts-row { grid-template-columns: 1fr 1fr; }
          .bottom-row { grid-template-columns: 1fr; }
        }
        @media (max-width: 640px) {
          .stats-grid { grid-template-columns: 1fr 1fr; }
          .charts-row { grid-template-columns: 1fr; }
        }
      `}</style>
    </div>
  )
}
