import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { getIncidents, getReport } from '../api'
import { FileText, Download, ChevronDown, ChevronUp, Shield, AlertTriangle, RefreshCw } from 'lucide-react'

function RiskScore({ score }) {
  const color = score >= 75 ? 'var(--critical)' : score >= 50 ? 'var(--high)' : 'var(--low)'
  return (
    <div className="risk-score-display">
      <svg viewBox="0 0 64 64" width={64} height={64}>
        <circle cx={32} cy={32} r={28} fill="none" stroke="var(--bg-elevated)" strokeWidth={8} />
        <circle
          cx={32} cy={32} r={28} fill="none" stroke={color} strokeWidth={8}
          strokeDasharray={`${(score / 100) * 175.9} 175.9`}
          strokeLinecap="round"
          transform="rotate(-90 32 32)"
        />
        <text x={32} y={37} textAnchor="middle" fill={color} fontSize="14" fontWeight="800" fontFamily="Inter">
          {score}
        </text>
      </svg>
      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>Risk Score</span>
    </div>
  )
}

function ReportCard({ incidentId }) {
  const [report, setReport]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [expanded, setExpanded] = useState(false)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await getReport(incidentId)
      setReport(data)
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load report')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [incidentId])

  const downloadReport = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${report.incident_id || incidentId}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const downloadHtml = () => {
    if (!report) return
    const html = generateHtmlReport(report)
    const blob = new Blob([html], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${report.incident_id || incidentId}.html`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="card report-card fade-in">
      <div className="report-card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <FileText size={16} style={{ color: 'var(--accent-cyan)' }} />
          <div>
            <p style={{ fontWeight: 600, fontSize: '0.88rem' }}>
              {report?.report_id || `REP-${incidentId.slice(0,8).toUpperCase()}`}
            </p>
            <p className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{incidentId}</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {report && <span className={`badge badge-${
            report.severity === 'Critical' ? 'critical' :
            report.severity === 'High' ? 'high' :
            report.severity === 'Medium' ? 'medium' : 'low'}`}>
            {report.severity}
          </span>}
          {report && (
            <>
              <button className="btn btn-ghost btn-sm" onClick={downloadReport}>
                <Download size={12} /> JSON
              </button>
              <button className="btn btn-primary btn-sm" onClick={downloadHtml}>
                <Download size={12} /> HTML
              </button>
            </>
          )}
          <button className="btn btn-ghost btn-sm" onClick={() => setExpanded(v => !v)}>
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {loading && <div style={{ padding: 20, textAlign: 'center' }}><div className="spinner" /></div>}
      {error && <p style={{ color: 'var(--critical)', fontSize: '0.83rem', padding: 12 }}>{error}</p>}

      {report && !loading && (
        <>
          <div className="report-summary-row">
            <RiskScore score={report.risk_score} />
            <div className="report-summary-stats">
              <div className="report-stat">
                <span className="section-title">Threat Category</span>
                <span className="badge badge-blue">{report.threat_category}</span>
              </div>
              <div className="report-stat">
                <span className="section-title">Events</span>
                <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{report.event_count}</span>
              </div>
              <div className="report-stat">
                <span className="section-title">MITRE Techniques</span>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {(report.mitre_techniques || []).map(t => (
                    <span key={t} className="badge badge-purple">{t}</span>
                  ))}
                  {(report.mitre_techniques || []).length === 0 && <span style={{ color: 'var(--text-dim)' }}>—</span>}
                </div>
              </div>
              <div className="report-stat">
                <span className="section-title">Generated</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  {new Date(report.generated_at).toLocaleString()}
                </span>
              </div>
            </div>
          </div>

          <div className="divider" />
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Executive Summary:</strong> {report.executive_summary}
          </p>

          {expanded && (
            <div className="report-expanded fade-in">
              <div className="divider" />
              <h4 className="section-title">Technical Analysis</h4>
              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.65, whiteSpace: 'pre-wrap' }}>
                {report.technical_analysis}
              </p>

              {/* IOCs */}
              {(report.indicators_of_compromise?.source_ips?.length > 0 ||
                report.indicators_of_compromise?.targeted_ports?.length > 0) && (
                <>
                  <div className="divider" />
                  <h4 className="section-title">Indicators of Compromise</h4>
                  <div className="ioc-grid">
                    {(report.indicators_of_compromise.source_ips || []).length > 0 && (
                      <div>
                        <p style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: 4 }}>Source IPs</p>
                        {report.indicators_of_compromise.source_ips.map(ip => (
                          <span key={ip} className="badge badge-critical mono" style={{ marginRight: 4 }}>{ip}</span>
                        ))}
                      </div>
                    )}
                    {(report.indicators_of_compromise.targeted_ports || []).length > 0 && (
                      <div>
                        <p style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: 4 }}>Targeted Ports</p>
                        {report.indicators_of_compromise.targeted_ports.map(p => (
                          <span key={p} className="badge badge-high mono" style={{ marginRight: 4 }}>{p}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* Threat Intel */}
              {report.threat_intelligence && (
                <>
                  <div className="divider" />
                  <h4 className="section-title">Threat Intelligence</h4>
                  <div className="intel-row">
                    <span>Malicious:</span>
                    <span style={{ color: report.threat_intelligence.is_malicious ? 'var(--critical)' : 'var(--low)' }}>
                      {report.threat_intelligence.is_malicious ? '⚠ Yes' : '✓ Clean'}
                    </span>
                    <span>VirusTotal:</span>
                    <span>{report.threat_intelligence.virustotal_score ?? '—'}</span>
                    <span>AbuseIPDB:</span>
                    <span>{report.threat_intelligence.abuseipdb_score ?? '—'}</span>
                  </div>
                  {(report.threat_intelligence.threat_labels || []).length > 0 && (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
                      {report.threat_intelligence.threat_labels.map(l => (
                        <span key={l} className="badge badge-high">{l}</span>
                      ))}
                    </div>
                  )}
                </>
              )}

              {/* Actions */}
              {(report.recommended_actions || []).length > 0 && (
                <>
                  <div className="divider" />
                  <h4 className="section-title">Recommended Actions</h4>
                  <ul style={{ paddingLeft: 18 }}>
                    {report.recommended_actions.map((a, i) => (
                      <li key={i} style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 4 }}>{a}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function generateHtmlReport(report) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SOC Report — ${report.report_id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #ffffff; color: #0f172a; max-width: 900px; margin: 40px auto; padding: 0 24px; }
    h1 { color: #0f172a; border-bottom: 2px solid #2563eb; padding-bottom: 12px; }
    h2 { font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.05em; color: #475569; margin-top: 24px; font-weight: 700; }
    p, li { color: #334155; line-height: 1.7; font-size: 0.9rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; margin: 2px; }
    .critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
    .high { background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; }
    .medium { background: #fef3c7; color: #d97706; border: 1px solid #fcd34d; }
    .low { background: #dcfce7; color: #16a34a; border: 1px solid #86efac; }
    .purple { background: #f5f3ff; color: #7c3aed; border: 1px solid #ddd6fe; }
    .risk { font-size: 2rem; font-weight: 800; color: ${report.risk_score >= 75 ? '#dc2626' : report.risk_score >= 50 ? '#ea580c' : '#16a34a'}; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 16px; border-radius: 8px; font-size: 0.82rem; overflow-x: auto; color: #0f172a; }
    .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 16px 0; }
    .meta div { background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px; border-radius: 6px; }
    .meta span.label { font-size: 0.7rem; color: #64748b; display: block; text-transform: uppercase; font-weight: 600; }
    .meta span.val { font-size: 0.9rem; color: #0f172a; font-weight: 600; }
  </style>
</head>
<body>
  <h1>🛡 Investigation Report — ${report.report_id}</h1>
  <div class="meta">
    <div><span class="label">Generated</span><span class="val">${new Date(report.generated_at).toLocaleString()}</span></div>
    <div><span class="label">Incident ID</span><span class="val">${report.incident_id}</span></div>
    <div><span class="label">Risk Score</span><span class="risk">${report.risk_score}<small style="font-size:1rem">/100</small></span></div>
    <div><span class="label">Severity</span><span class="val"><span class="badge ${(report.severity || '').toLowerCase()}">${report.severity}</span></span></div>
  </div>
  <h2>Executive Summary</h2>
  <p>${report.executive_summary}</p>
  <h2>Technical Analysis</h2>
  <p>${report.technical_analysis}</p>
  <h2>MITRE ATT&CK Techniques</h2>
  <p>${(report.mitre_techniques || []).map(t => `<span class="badge purple">${t}</span>`).join(' ') || 'None identified'}</p>
  <h2>Indicators of Compromise</h2>
  <p>Source IPs: ${(report.indicators_of_compromise?.source_ips || []).join(', ') || '—'}</p>
  <p>Targeted Ports: ${(report.indicators_of_compromise?.targeted_ports || []).join(', ') || '—'}</p>
  <h2>Recommended Actions</h2>
  <ul>${(report.recommended_actions || []).map(a => `<li>${a}</li>`).join('')}</ul>
  <hr style="border-color:#21262d; margin-top:40px">
  <p style="color:#8b949e; font-size:0.78rem">Generated by Agentic AI SOC Analyst v0.3.0</p>
</body>
</html>`
}

export default function Reports() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]     = useState(true)
  const location = useLocation()
  const preselect = new URLSearchParams(location.search).get('incident')

  useEffect(() => {
    getIncidents()
      .then(({ data }) => setIncidents(data || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const sorted = preselect
    ? [
        ...incidents.filter(i => i.incident_id === preselect),
        ...incidents.filter(i => i.incident_id !== preselect),
      ]
    : incidents

  return (
    <div className="reports-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Investigation Reports</h1>
          <p className="page-subtitle">{incidents.length} incidents · Click an incident to expand its report</p>
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
          <div className="spinner" style={{ width: 28, height: 28 }} />
        </div>
      ) : incidents.length === 0 ? (
        <div className="empty-state card" style={{ padding: 64 }}>
          <FileText size={40} style={{ opacity: 0.3 }} />
          <p>No incidents available. Run the pipeline to generate reports.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {sorted.map(inc => (
            <ReportCard key={inc.incident_id} incidentId={inc.incident_id} />
          ))}
        </div>
      )}

      <style>{`
        .reports-page { display: flex; flex-direction: column; gap: 16px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; }
        .page-title { font-size: 1.3rem; font-weight: 700; }
        .page-subtitle { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }

        .report-card { display: flex; flex-direction: column; gap: 12px; }
        .report-card-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
        .report-summary-row { display: flex; align-items: flex-start; gap: 20px; flex-wrap: wrap; }
        .risk-score-display { display: flex; flex-direction: column; align-items: center; }
        .report-summary-stats { flex: 1; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .report-stat { display: flex; flex-direction: column; gap: 4px; }
        .report-expanded { display: flex; flex-direction: column; gap: 12px; }
        .ioc-grid { display: flex; gap: 20px; flex-wrap: wrap; }
        .intel-row { display: grid; grid-template-columns: auto auto auto auto auto auto; gap: 8px 16px; align-items: center; font-size: 0.83rem; color: var(--text-muted); }
      `}</style>
    </div>
  )
}
