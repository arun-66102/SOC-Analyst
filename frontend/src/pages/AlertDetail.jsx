import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getAlert, getReport } from '../api'
import { ArrowLeft, Shield, AlertTriangle, Search, FileText, Network, CheckCircle } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'
import AnalystActionPanel from '../components/AnalystActionPanel'



function InfoRow({ label, value, mono }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className={`info-value ${mono ? 'mono' : ''}`}>{value ?? '—'}</span>
    </div>
  )
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="card detail-section">
      <div className="section-header">
        <Icon size={14} style={{ color: 'var(--accent-cyan)' }} />
        <h3 className="section-heading">{title}</h3>
      </div>
      {children}
    </div>
  )
}

export default function AlertDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [alert, setAlert]     = useState(null)
  const [report, setReport]   = useState(null)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    setLoading(true)
    getAlert(id)
      .then(({ data }) => {
        setAlert(data)
        if (data.incident_id) {
          getReport(data.incident_id)
            .then(r => setReport(r.data))
            .catch(() => {})
        }
      })
      .catch(e => console.error(e))
      .finally(() => setLoading(false))
  }, [id])

  const handleActionSuccess = async (newStatus) => {
    // Refresh the alert to reflect updated status
    try {
      const { data } = await getAlert(id)
      setAlert(data)
    } catch (_) {}
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
        <div className="spinner" style={{ width: 32, height: 32 }} />
      </div>
    )
  }

  if (!alert) {
    return (
      <div className="empty-state">
        <AlertTriangle size={32} />
        <p>Alert not found</p>
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')}>Back to Alerts</button>
      </div>
    )
  }

  const enrichment = alert.enrichment_data || {}

  return (
    <div className="alert-detail-page fade-in">
      {/* Back */}
      <button className="btn btn-ghost btn-sm back-btn" onClick={() => navigate('/alerts')}>
        <ArrowLeft size={14} /> Back to Alerts
      </button>

      {/* Header */}
      <div className="detail-header card">
        <div className="detail-header-left">
          <SeverityBadge sev={alert.severity} />
          <span className="badge badge-blue">{alert.status}</span>
          {alert.is_true_positive !== null && alert.is_true_positive !== undefined && (
            alert.is_true_positive
              ? <span className="badge badge-green">True Positive</span>
              : <span className="badge badge-unknown">False Positive</span>
          )}
        </div>
        <div className="detail-header-right">
          <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
            {alert.event_id}
          </span>
        </div>
      </div>

      <div className="detail-grid">
        {/* Event Details */}
        <Section title="Event Details" icon={Network}>
          <InfoRow label="Threat Category" value={alert.threat_category} />
          <InfoRow label="Source IP"       value={alert.src_ip}         mono />
          <InfoRow label="Destination IP"  value={alert.dst_ip}         mono />
          <InfoRow label="Src Port"        value={alert.src_port}       mono />
          <InfoRow label="Dst Port"        value={alert.dst_port}       mono />
          <InfoRow label="Protocol"        value={alert.protocol}       mono />
          <InfoRow label="Flow Duration"   value={alert.flow_duration ? `${alert.flow_duration.toFixed(2)}s` : null} />
          <InfoRow label="Fwd Packets"     value={alert.total_fwd_packets} />
          <InfoRow label="Bwd Packets"     value={alert.total_bwd_packets} />
          <InfoRow label="Source Dataset"  value={alert.source_dataset} />
          <InfoRow label="Timestamp"       value={new Date(alert.timestamp).toLocaleString()} />
          <InfoRow label="Incident ID"     value={alert.incident_id}    mono />
        </Section>

        {/* MITRE Techniques */}
        <Section title="MITRE ATT&CK Techniques" icon={Shield}>
          {(alert.mitre_techniques || []).length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {alert.mitre_techniques.map(t => (
                <div key={t} className="mitre-tag">
                  <span className="badge badge-purple">{t}</span>
                  <a
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}
                  >
                    View on MITRE →
                  </a>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No MITRE techniques identified</p>
          )}
          {alert.correlation_summary && (
            <>
              <div className="divider" />
              <p className="section-title">Correlation Summary</p>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {alert.correlation_summary}
              </p>
            </>
          )}
        </Section>

        {/* Threat Intelligence */}
        <Section title="Threat Intelligence" icon={Search}>
          <InfoRow label="Malicious" value={
            enrichment.is_malicious === undefined ? '—'
              : enrichment.is_malicious ? '⚠ Yes' : '✓ Clean'
          } />
          <InfoRow label="VirusTotal Score" value={enrichment.virustotal_score} />
          <InfoRow label="AbuseIPDB Score"  value={enrichment.abuseipdb_score} />
          <InfoRow label="Confidence"       value={enrichment.confidence ? `${(enrichment.confidence * 100).toFixed(0)}%` : null} />
          {(enrichment.threat_labels || []).length > 0 && (
            <>
              <div className="divider" />
              <p className="section-title">Threat Labels</p>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {enrichment.threat_labels.map(l => (
                  <span key={l} className="badge badge-high">{l}</span>
                ))}
              </div>
            </>
          )}
        </Section>

        {/* Investigation Report */}
        {report && (
          <Section title="Investigation Report" icon={FileText}>
            <div className="risk-score-bar">
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Risk Score</span>
              <div className="risk-bar-track">
                <div
                  className="risk-bar-fill"
                  style={{
                    width: `${report.risk_score}%`,
                    background: report.risk_score >= 75 ? 'var(--critical)' : report.risk_score >= 50 ? 'var(--high)' : 'var(--low)',
                  }}
                />
              </div>
              <span className="mono" style={{ fontSize: '0.85rem', fontWeight: 700 }}>{report.risk_score}/100</span>
            </div>
            <div className="divider" />
            <p className="section-title">Executive Summary</p>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {report.executive_summary}
            </p>
            {(report.recommended_actions || []).length > 0 && (
              <>
                <div className="divider" />
                <p className="section-title">Recommended Actions</p>
                <ul style={{ paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {report.recommended_actions.map((a, i) => (
                    <li key={i} style={{ fontSize: '0.83rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{a}</li>
                  ))}
                </ul>
              </>
            )}
          </Section>
        )}

        {/* Analyst Actions */}
        <Section title="Analyst Actions" icon={CheckCircle}>
          <AnalystActionPanel
            alertId={id}
            currentStatus={alert.status}
            onSuccess={handleActionSuccess}
          />
        </Section>
      </div>

      <style>{`
        .alert-detail-page { display: flex; flex-direction: column; gap: 16px; }
        .back-btn { margin-bottom: 4px; width: fit-content; }
        .detail-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; }
        .detail-header-left { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

        .detail-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }
        .detail-section { display: flex; flex-direction: column; gap: 0; }
        .section-header { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; }
        .section-heading { font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-secondary); }

        .info-row { display: flex; align-items: baseline; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border-subtle); gap: 12px; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-size: 0.75rem; color: var(--text-muted); white-space: nowrap; flex-shrink: 0; }
        .info-value { font-size: 0.85rem; color: var(--text-primary); text-align: right; word-break: break-all; }

        .mitre-tag { display: flex; align-items: center; justify-content: space-between; gap: 8px; }

        .risk-score-bar { display: flex; align-items: center; gap: 10px; }
        .risk-bar-track { flex: 1; height: 8px; background: var(--bg-elevated); border-radius: 4px; overflow: hidden; }
        .risk-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s; }

        .action-buttons { display: flex; gap: 8px; flex-wrap: wrap; }

        @media (max-width: 768px) {
          .detail-grid { grid-template-columns: 1fr; }
        }
      `}</style>
    </div>
  )
}
