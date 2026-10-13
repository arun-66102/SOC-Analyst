import { useState } from 'react'
import { analyzeEvent } from '../api'
import { useNavigate } from 'react-router-dom'
import { Cpu, Play, ChevronDown, ChevronUp, CheckCircle, XCircle, Clock } from 'lucide-react'

const CATEGORIES = ['BruteForce', 'DoS', 'DDoS', 'PortScan', 'Infiltration', 'WebAttack', 'Botnet', 'Malware', 'Exfiltration', 'Backdoor', 'Reconnaissance', 'Benign', 'Unknown']

const EXAMPLE_EVENTS = [
  {
    label: 'SSH Brute Force',
    event: {
      event_id: crypto.randomUUID ? crypto.randomUUID() : 'evt-brute-1',
      src_ip: '185.220.101.47',
      dst_ip: '10.0.0.5',
      src_port: 54321,
      dst_port: 22,
      protocol: 'TCP',
      threat_category: 'BruteForce',
      total_fwd_packets: 1200,
      total_bwd_packets: 80,
      flow_duration: 45.2,
      flow_bytes_per_sec: 2400.5,
      label: 'SSH-Brute-Force',
    },
  },
  {
    label: 'Malware C2 Beacon',
    event: {
      event_id: crypto.randomUUID ? crypto.randomUUID() : 'evt-malware-1',
      src_ip: '10.0.0.23',
      dst_ip: '45.142.212.100',
      src_port: 49152,
      dst_port: 443,
      protocol: 'TCP',
      threat_category: 'Malware',
      total_fwd_packets: 28,
      total_bwd_packets: 25,
      flow_duration: 3600.0,
      flow_bytes_per_sec: 128.5,
      label: 'C2-Beacon',
    },
  },
  {
    label: 'Port Scan',
    event: {
      event_id: crypto.randomUUID ? crypto.randomUUID() : 'evt-scan-1',
      src_ip: '192.168.1.254',
      dst_ip: '10.0.0.1',
      src_port: null,
      dst_port: null,
      protocol: 'TCP',
      threat_category: 'PortScan',
      total_fwd_packets: 5000,
      total_bwd_packets: 0,
      flow_duration: 12.5,
      flow_bytes_per_sec: 95000.0,
      label: 'PortScan',
    },
  },
  {
    label: 'Data Exfiltration',
    event: {
      event_id: crypto.randomUUID ? crypto.randomUUID() : 'evt-exfil-1',
      src_ip: '10.0.0.15',
      dst_ip: '104.21.42.101',
      src_port: 49200,
      dst_port: 80,
      protocol: 'TCP',
      threat_category: 'Exfiltration',
      total_fwd_packets: 850,
      total_bwd_packets: 45,
      flow_duration: 120.0,
      flow_bytes_per_sec: 52000.0,
      label: 'Data-Exfiltration',
    },
  },
]

function ResultStage({ label, result, color }) {
  const [open, setOpen] = useState(false)
  if (!result) return (
    <div className="stage-row stage-skipped">
      <span className="stage-label">{label}</span>
      <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>Skipped</span>
    </div>
  )
  const ok = result.status === 'success'
  return (
    <div className={`stage-row ${ok ? 'stage-ok' : 'stage-err'}`}>
      <div className="stage-header" onClick={() => setOpen(v => !v)}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {ok ? <CheckCircle size={13} color="var(--low)" /> : <XCircle size={13} color="var(--critical)" />}
          <span className="stage-label">{label}</span>
          {result.agent_name && <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>({result.agent_name})</span>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {result.latency_ms && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <Clock size={10} /> {result.latency_ms.toFixed(0)}ms
            </span>
          )}
          {result.confidence != null && (
            <span style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
              {(result.confidence * 100).toFixed(0)}% conf.
            </span>
          )}
          {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </div>
      </div>
      {result.reasoning && (
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.5 }}>
          {result.reasoning.slice(0, 200)}{result.reasoning.length > 200 ? '…' : ''}
        </p>
      )}
      {open && result.output && (
        <pre className="result-json">{JSON.stringify(result.output, null, 2)}</pre>
      )}
      {open && result.error_message && (
        <p style={{ color: 'var(--critical)', fontSize: '0.82rem', marginTop: 6 }}>{result.error_message}</p>
      )}
    </div>
  )
}

export default function Analyze() {
  const navigate = useNavigate()
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState('')
  const [form, setForm]         = useState({
    src_ip: '192.168.1.100',
    dst_ip: '10.0.0.5',
    src_port: '',
    dst_port: '22',
    protocol: 'TCP',
    threat_category: 'BruteForce',
    label: '',
    flow_duration: '',
    total_fwd_packets: '',
    total_bwd_packets: '',
    flow_bytes_per_sec: '',
  })

  const loadExample = (ex) => {
    const e = ex.event
    setForm({
      src_ip:              e.src_ip || '',
      dst_ip:              e.dst_ip || '',
      src_port:            e.src_port ?? '',
      dst_port:            e.dst_port ?? '',
      protocol:            e.protocol || 'TCP',
      threat_category:     e.threat_category || 'Unknown',
      label:               e.label || '',
      flow_duration:       e.flow_duration ?? '',
      total_fwd_packets:   e.total_fwd_packets ?? '',
      total_bwd_packets:   e.total_bwd_packets ?? '',
      flow_bytes_per_sec:  e.flow_bytes_per_sec ?? '',
    })
    setResult(null)
    setError('')
  }

  const run = async () => {
    setLoading(true)
    setResult(null)
    setError('')
    try {
      const event = {
        event_id: `evt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,6)}`,
        src_ip:              form.src_ip || null,
        dst_ip:              form.dst_ip || null,
        src_port:            form.src_port ? parseInt(form.src_port) : null,
        dst_port:            form.dst_port ? parseInt(form.dst_port) : null,
        protocol:            form.protocol || null,
        threat_category:     form.threat_category || 'Unknown',
        label:               form.label || null,
        flow_duration:       form.flow_duration ? parseFloat(form.flow_duration) : null,
        total_fwd_packets:   form.total_fwd_packets ? parseInt(form.total_fwd_packets) : null,
        total_bwd_packets:   form.total_bwd_packets ? parseInt(form.total_bwd_packets) : null,
        flow_bytes_per_sec:  form.flow_bytes_per_sec ? parseFloat(form.flow_bytes_per_sec) : null,
      }
      const { data } = await analyzeEvent(event)
      setResult(data)
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Pipeline failed')
    } finally {
      setLoading(false)
    }
  }

  const f = (field) => (e) => setForm(v => ({ ...v, [field]: e.target.value }))

  return (
    <div className="analyze-page fade-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Analyze Event</h1>
          <p className="page-subtitle">Trigger the full AI agent pipeline on a security event</p>
        </div>
      </div>

      {/* Example events */}
      <div className="card" style={{ padding: '14px 18px' }}>
        <p className="section-title" style={{ marginBottom: 10 }}>Quick Examples</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {EXAMPLE_EVENTS.map(ex => (
            <button key={ex.label} className="btn btn-ghost btn-sm" onClick={() => loadExample(ex)}>
              {ex.label}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <div className="card analyze-form">
        <h3 className="chart-title" style={{ marginBottom: 16 }}>Event Parameters</h3>
        <div className="form-grid">
          <div className="form-field">
            <label className="field-label">Threat Category *</label>
            <select className="select" value={form.threat_category} onChange={f('threat_category')}>
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div className="form-field">
            <label className="field-label">Protocol</label>
            <select className="select" value={form.protocol} onChange={f('protocol')}>
              {['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <div className="form-field">
            <label className="field-label">Source IP</label>
            <input className="input" value={form.src_ip} onChange={f('src_ip')} placeholder="e.g. 192.168.1.100" />
          </div>
          <div className="form-field">
            <label className="field-label">Destination IP</label>
            <input className="input" value={form.dst_ip} onChange={f('dst_ip')} placeholder="e.g. 10.0.0.5" />
          </div>
          <div className="form-field">
            <label className="field-label">Source Port</label>
            <input className="input" value={form.src_port} onChange={f('src_port')} placeholder="e.g. 54321" type="number" />
          </div>
          <div className="form-field">
            <label className="field-label">Destination Port</label>
            <input className="input" value={form.dst_port} onChange={f('dst_port')} placeholder="e.g. 22" type="number" />
          </div>
          <div className="form-field">
            <label className="field-label">Flow Duration (s)</label>
            <input className="input" value={form.flow_duration} onChange={f('flow_duration')} placeholder="e.g. 45.2" type="number" step="0.1" />
          </div>
          <div className="form-field">
            <label className="field-label">Fwd Packets</label>
            <input className="input" value={form.total_fwd_packets} onChange={f('total_fwd_packets')} placeholder="e.g. 1200" type="number" />
          </div>
          <div className="form-field">
            <label className="field-label">Bwd Packets</label>
            <input className="input" value={form.total_bwd_packets} onChange={f('total_bwd_packets')} placeholder="e.g. 80" type="number" />
          </div>
          <div className="form-field">
            <label className="field-label">Flow Bytes/sec</label>
            <input className="input" value={form.flow_bytes_per_sec} onChange={f('flow_bytes_per_sec')} placeholder="e.g. 2400.5" type="number" step="0.1" />
          </div>
          <div className="form-field" style={{ gridColumn: '1 / -1' }}>
            <label className="field-label">Label / Description</label>
            <input className="input" value={form.label} onChange={f('label')} placeholder="e.g. SSH-Brute-Force" />
          </div>
        </div>

        <button
          className="btn btn-primary"
          style={{ marginTop: 16, width: '100%', justifyContent: 'center' }}
          onClick={run}
          disabled={loading}
        >
          {loading ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Running Pipeline…</> : <><Play size={14} /> Run AI Pipeline</>}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="card" style={{ borderColor: 'rgba(255,45,85,0.3)', background: 'var(--critical-dim)', padding: '14px 18px' }}>
          <p style={{ color: 'var(--critical)', fontSize: '0.88rem' }}>⚠ {error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="card result-card fade-in">
          <div className="result-header">
            <div>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700 }}>Pipeline Results</h3>
              <p className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                Run: {result.pipeline_run_id} · Event: {result.event_id}
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {result.total_latency_ms && (
                <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                  <Clock size={12} style={{ display: 'inline', marginRight: 4 }} />
                  {result.total_latency_ms.toFixed(0)}ms total
                </span>
              )}
              <button
                className="btn btn-primary btn-sm"
                onClick={() => navigate(`/alerts/${result.event_id}`)}
              >
                View Alert →
              </button>
            </div>
          </div>
          <div className="stages-list">
            <ResultStage label="1. Triage"         result={result.triage}         />
            <ResultStage label="2. Correlation"    result={result.correlation}    />
            <ResultStage label="3. MITRE Mapping"  result={result.mitre}          />
            <ResultStage label="4. Enrichment"     result={result.enrichment}     />
            <ResultStage label="5. Investigation"  result={result.investigation}  />
            <ResultStage label="6. Report"         result={result.report}         />
          </div>
        </div>
      )}

      <style>{`
        .analyze-page { display: flex; flex-direction: column; gap: 16px; }
        .page-header { display: flex; align-items: flex-start; justify-content: space-between; }
        .page-title { font-size: 1.3rem; font-weight: 700; }
        .page-subtitle { font-size: 0.82rem; color: var(--text-muted); margin-top: 2px; }
        .chart-title { font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }

        .analyze-form { }
        .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .form-field { display: flex; flex-direction: column; gap: 4px; }
        .field-label { font-size: 0.72rem; color: var(--text-muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.04em; }

        .result-card { }
        .result-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; gap: 12px; flex-wrap: wrap; }
        .stages-list { display: flex; flex-direction: column; gap: 8px; }
        .stage-row {
          border: 1px solid var(--border-subtle);
          border-radius: 8px;
          padding: 10px 14px;
          background: #ffffff;
          box-shadow: var(--shadow-sm);
          transition: border-color 0.15s, box-shadow 0.15s;
        }
        .stage-ok  { border-color: #86efac; background: #f0fdf4; }
        .stage-err { border-color: #fca5a5; background: #fef2f2; }
        .stage-skipped { display: flex; align-items: center; justify-content: space-between; opacity: 0.6; background: #f8fafc; }
        .stage-header { display: flex; align-items: center; justify-content: space-between; cursor: pointer; }
        .stage-label { font-size: 0.85rem; font-weight: 700; color: var(--text-primary); }
        .result-json {
          margin-top: 10px;
          background: #f8fafc;
          border: 1px solid var(--border-subtle);
          border-radius: 6px;
          padding: 12px;
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: #0f172a;
          overflow-x: auto;
          max-height: 300px;
          overflow-y: auto;
          line-height: 1.5;
        }

        @media (max-width: 640px) {
          .form-grid { grid-template-columns: 1fr; }
        }
      `}</style>
    </div>
  )
}
