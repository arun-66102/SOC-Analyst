import { useState, useEffect } from 'react'
import { getAlerts } from '../api'
import { Shield, ExternalLink, RefreshCw, Info } from 'lucide-react'

// Full MITRE ATT&CK technique metadata for the most common ones
const MITRE_INFO = {
  'T1110': { name: 'Brute Force', tactic: 'Credential Access', color: '#ff2d55' },
  'T1046': { name: 'Network Service Discovery', tactic: 'Discovery', color: '#ff9500' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'Command & Control', color: '#8b5cf6' },
  'T1048': { name: 'Exfiltration Over Alt Protocol', tactic: 'Exfiltration', color: '#ff2d55' },
  'T1498': { name: 'Network DoS', tactic: 'Impact', color: '#ff9500' },
  'T1566': { name: 'Phishing', tactic: 'Initial Access', color: '#3b82f6' },
  'T1059': { name: 'Command & Scripting Interpreter', tactic: 'Execution', color: '#ffcc00' },
  'T1078': { name: 'Valid Accounts', tactic: 'Defense Evasion', color: '#10b981' },
  'T1021': { name: 'Remote Services', tactic: 'Lateral Movement', color: '#06b6d4' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'Persistence', color: '#8b5cf6' },
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access', color: '#3b82f6' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access', color: '#ff2d55' },
  'T1082': { name: 'System Information Discovery', tactic: 'Discovery', color: '#ff9500' },
  'T1055': { name: 'Process Injection', tactic: 'Defense Evasion', color: '#ffcc00' },
  'T1036': { name: 'Masquerading', tactic: 'Defense Evasion', color: '#ffcc00' },
}

const TACTIC_ORDER = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command & Control', 'Exfiltration', 'Impact',
]

const TACTIC_COLORS = {
  'Initial Access':      '#3b82f6',
  'Execution':           '#8b5cf6',
  'Persistence':         '#06b6d4',
  'Privilege Escalation':'#f59e0b',
  'Defense Evasion':     '#ffcc00',
  'Credential Access':   '#ff2d55',
  'Discovery':           '#ff9500',
  'Lateral Movement':    '#10b981',
  'Collection':          '#6366f1',
  'Command & Control':   '#ec4899',
  'Exfiltration':        '#ef4444',
  'Impact':              '#dc2626',
}

export default function MitrePage() {
  const [alerts, setAlerts]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [selected, setSelected]   = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await getAlerts({ limit: 500 })
      setAlerts(data.alerts || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Build technique frequency map
  const techCounts = {}
  alerts.forEach(a => {
    (a.mitre_techniques || []).forEach(t => {
      techCounts[t] = (techCounts[t] || 0) + 1
    })
  })

  const maxCount = Math.max(1, ...Object.values(techCounts))

  // Group by tactic
  const byTactic = {}
  Object.entries(techCounts).forEach(([tech, count]) => {
    const info = MITRE_INFO[tech]
    const tactic = info?.tactic || 'Unknown'
    if (!byTactic[tactic]) byTactic[tactic] = []
    byTactic[tactic].push({ tech, count, info })
  })

  // Sorted tactics
  const allTactics = [
    ...TACTIC_ORDER.filter(t => byTactic[t]),
    ...Object.keys(byTactic).filter(t => !TACTIC_ORDER.includes(t)),
  ]

  return (
    <div className="mitre-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">MITRE ATT&CK Coverage</h1>
          <p className="page-subtitle">
            {Object.keys(techCounts).length} techniques detected across {alerts.length} alerts
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
          <div className="spinner" style={{ width: 28, height: 28 }} />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Heatmap */}
          <div className="card">
            <h3 className="chart-title">
              <Shield size={13} style={{ display: 'inline', marginRight: 6 }} />
              Attack Technique Heatmap
            </h3>
            {allTactics.length === 0 ? (
              <div className="empty-state" style={{ padding: 40 }}>
                <Shield size={32} />
                <p>No MITRE techniques detected yet. Analyze some events to populate this view.</p>
              </div>
            ) : (
              <div className="heatmap-grid">
                {allTactics.map(tactic => (
                  <div key={tactic} className="tactic-column">
                    <div
                      className="tactic-header"
                      style={{ background: `${TACTIC_COLORS[tactic] || '#636366'}22`, color: TACTIC_COLORS[tactic] || '#636366' }}
                    >
                      {tactic}
                    </div>
                    {byTactic[tactic].map(({ tech, count, info }) => {
                      const intensity = count / maxCount
                      const bgColor = TACTIC_COLORS[tactic] || '#636366'
                      return (
                        <div
                          key={tech}
                          className="technique-cell"
                          style={{
                            background: `${bgColor}${Math.round(intensity * 0.7 * 255).toString(16).padStart(2,'0')}`,
                            border: selected?.tech === tech ? `1px solid ${bgColor}` : '1px solid transparent',
                          }}
                          onClick={() => setSelected(selected?.tech === tech ? null : { tech, count, info })}
                          title={`${tech} — ${info?.name || tech} (${count} occurrences)`}
                        >
                          <span className="mono" style={{ fontSize: '0.7rem', fontWeight: 600 }}>{tech}</span>
                          <span style={{ fontSize: '0.65rem', opacity: 0.7 }}>{info?.name?.slice(0, 20) || '—'}</span>
                          <span className="technique-count">{count}</span>
                        </div>
                      )
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Selected technique detail */}
          {selected && (
            <div className="card technique-detail fade-in">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                <Info size={14} style={{ color: 'var(--accent-cyan)' }} />
                <h3 style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                  {selected.tech} — {selected.info?.name || 'Unknown Technique'}
                </h3>
                <a
                  href={`https://attack.mitre.org/techniques/${selected.tech.replace('.', '/')}`}
                  target="_blank" rel="noopener noreferrer"
                  className="btn btn-ghost btn-sm"
                  style={{ marginLeft: 'auto' }}
                >
                  MITRE Website <ExternalLink size={11} />
                </a>
              </div>
              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                <div>
                  <span className="section-title">Tactic</span>
                  <span className="badge badge-purple">{selected.info?.tactic || 'Unknown'}</span>
                </div>
                <div>
                  <span className="section-title">Detection Count</span>
                  <span style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                    {selected.count}
                  </span>
                </div>
                <div>
                  <span className="section-title">Technique ID</span>
                  <span className="badge badge-blue mono">{selected.tech}</span>
                </div>
              </div>
            </div>
          )}

          {/* Technique frequency table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
              <h3 className="chart-title" style={{ margin: 0 }}>Technique Frequency Table</h3>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Technique ID</th>
                  <th>Name</th>
                  <th>Tactic</th>
                  <th>Count</th>
                  <th>Frequency</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(techCounts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([tech, count]) => {
                    const info = MITRE_INFO[tech]
                    const pct = Math.round((count / maxCount) * 100)
                    return (
                      <tr key={tech}>
                        <td><span className="badge badge-purple mono">{tech}</span></td>
                        <td style={{ color: 'var(--text-secondary)' }}>{info?.name || '—'}</td>
                        <td>
                          {info?.tactic ? (
                            <span style={{ fontSize: '0.78rem', color: TACTIC_COLORS[info.tactic] || 'var(--text-muted)' }}>
                              {info.tactic}
                            </span>
                          ) : '—'}
                        </td>
                        <td style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{count}</td>
                        <td>
                          <div className="freq-bar-track">
                            <div
                              className="freq-bar-fill"
                              style={{
                                width: `${pct}%`,
                                background: info ? TACTIC_COLORS[info.tactic] || 'var(--accent-blue)' : 'var(--accent-blue)',
                              }}
                            />
                          </div>
                        </td>
                        <td>
                          <a
                            href={`https://attack.mitre.org/techniques/${tech.replace('.', '/')}`}
                            target="_blank" rel="noopener noreferrer"
                            style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}
                          >
                            <ExternalLink size={12} />
                          </a>
                        </td>
                      </tr>
                    )
                  })}
                {Object.keys(techCounts).length === 0 && (
                  <tr>
                    <td colSpan={6}>
                      <div className="empty-state">
                        <Shield size={28} />
                        <p>No techniques detected yet</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <style>{`
        .mitre-page { display: flex; flex-direction: column; gap: 16px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; }
        .page-title { font-size: 1.3rem; font-weight: 700; }
        .page-subtitle { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }
        .chart-title { font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 14px; }

        .heatmap-grid {
          display: flex;
          gap: 8px;
          overflow-x: auto;
          padding-bottom: 8px;
        }
        .tactic-column { min-width: 140px; display: flex; flex-direction: column; gap: 4px; }
        .tactic-header {
          padding: 6px 8px;
          border-radius: 6px;
          font-size: 0.68rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          text-align: center;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .technique-cell {
          padding: 8px;
          border-radius: 6px;
          cursor: pointer;
          display: flex;
          flex-direction: column;
          gap: 2px;
          position: relative;
          background: #ffffff;
          border: 1px solid var(--border-subtle);
          transition: opacity 0.15s, border-color 0.15s, box-shadow 0.15s;
        }
        .technique-cell:hover { border-color: var(--border-glow); box-shadow: var(--shadow-sm); }
        .technique-count {
          position: absolute; top: 4px; right: 6px;
          font-size: 0.68rem; font-weight: 800;
          color: var(--text-secondary);
        }

        .technique-detail { }
        .freq-bar-track { width: 100px; height: 6px; background: var(--bg-elevated); border-radius: 3px; overflow: hidden; }
        .freq-bar-fill { height: 100%; border-radius: 3px; }
      `}</style>
    </div>
  )
}
