/**
 * components/AnalystActionPanel.jsx
 * ----------------------------------
 * Reusable analyst action panel: Approve / Escalate / Dismiss
 * with an optional comment textarea and status feedback.
 *
 * Props:
 *   alertId      — string  event_id of the alert to act on
 *   currentStatus — string current alert.status value
 *   onSuccess    — Function(newStatus) callback after successful action
 */

import { useState } from 'react'
import { CheckCircle, ArrowUpCircle, XCircle } from 'lucide-react'
import { postAction } from '../api'

export default function AnalystActionPanel({ alertId, currentStatus, onSuccess }) {
  const [comment, setComment]     = useState('')
  const [loading, setLoading]     = useState(false)
  const [message, setMessage]     = useState('')
  const [isError, setIsError]     = useState(false)

  const takeAction = async (action) => {
    setLoading(true)
    setMessage('')
    try {
      const { data } = await postAction(alertId, {
        action,
        comment,
        analyst_id: 'analyst-1',
      })
      const newStatus = data.new_alert_status || action
      setMessage(`✓ Action '${data.action}' recorded. Status: ${newStatus}`)
      setIsError(false)
      setComment('')
      onSuccess && onSuccess(newStatus)
    } catch (e) {
      setMessage(`✗ Error: ${e.response?.data?.detail || e.message}`)
      setIsError(true)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        Current Status:{' '}
        <strong style={{ color: 'var(--text-primary)' }}>{currentStatus}</strong>
      </p>

      <textarea
        id={`analyst-comment-${alertId}`}
        className="input"
        rows={2}
        placeholder="Add a comment (optional)…"
        value={comment}
        onChange={e => setComment(e.target.value)}
        style={{ resize: 'vertical', fontFamily: 'var(--font-sans)' }}
      />

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          id={`action-approve-${alertId}`}
          className="btn btn-success btn-sm"
          disabled={loading}
          onClick={() => takeAction('approve')}
        >
          <CheckCircle size={13} /> Approve
        </button>
        <button
          id={`action-escalate-${alertId}`}
          className="btn btn-primary btn-sm"
          style={{ background: 'var(--high)', color: '#fff' }}
          disabled={loading}
          onClick={() => takeAction('escalate')}
        >
          <ArrowUpCircle size={13} /> Escalate
        </button>
        <button
          id={`action-dismiss-${alertId}`}
          className="btn btn-ghost btn-sm"
          disabled={loading}
          onClick={() => takeAction('dismiss')}
        >
          <XCircle size={13} /> Dismiss
        </button>
      </div>

      {message && (
        <div
          style={{
            fontSize: '0.82rem',
            padding: '8px 12px',
            borderRadius: 6,
            background: isError ? 'var(--critical-dim)' : 'var(--low-dim)',
            color:      isError ? 'var(--critical)'     : 'var(--low)',
            border: `1px solid ${isError ? 'rgba(220,38,38,0.3)' : 'rgba(22,163,74,0.3)'}`,
          }}
        >
          {message}
        </div>
      )}
    </div>
  )
}
