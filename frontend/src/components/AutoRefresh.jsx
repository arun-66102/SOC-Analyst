/**
 * components/AutoRefresh.jsx
 * --------------------------
 * Hook and indicator component for 5-second auto-refresh polling.
 *
 * Usage:
 *   import { useAutoRefresh, AutoRefreshBadge } from '../components/AutoRefresh'
 *
 *   const { lastRefresh, manualRefresh } = useAutoRefresh(loadData, 5000)
 *   <AutoRefreshBadge lastRefresh={lastRefresh} onRefresh={manualRefresh} />
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { RefreshCw } from 'lucide-react'

/**
 * useAutoRefresh — fires `fetchFn` immediately and then every `intervalMs`.
 *
 * @param {Function} fetchFn       async data-loading function
 * @param {number}   intervalMs    polling interval (default 5000 ms)
 * @returns {{ lastRefresh: Date|null, manualRefresh: Function }}
 */
export function useAutoRefresh(fetchFn, intervalMs = 5000) {
  const [lastRefresh, setLastRefresh] = useState(null)
  const fetchRef = useRef(fetchFn)

  // Keep ref in sync so the interval always sees the latest version of fetchFn
  useEffect(() => { fetchRef.current = fetchFn }, [fetchFn])

  const run = useCallback(async () => {
    await fetchRef.current()
    setLastRefresh(new Date())
  }, [])

  useEffect(() => {
    run()
    const id = setInterval(run, intervalMs)
    return () => clearInterval(id)
  }, [run, intervalMs])

  return { lastRefresh, manualRefresh: run }
}

/**
 * AutoRefreshBadge — small indicator showing last-refresh time and a manual-
 * refresh button. Designed to sit in a PageHeader's `actions` slot.
 *
 * Props:
 *   lastRefresh — Date | null
 *   onRefresh   — Function  called when the user clicks the refresh button
 *   spinning    — boolean   show spinner animation while loading
 */
export function AutoRefreshBadge({ lastRefresh, onRefresh, spinning = false }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {lastRefresh && (
        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
          Updated {lastRefresh.toLocaleTimeString()}
        </span>
      )}
      <button
        id="auto-refresh-btn"
        className="btn btn-ghost btn-sm"
        onClick={onRefresh}
        title="Refresh now"
      >
        <RefreshCw
          size={14}
          style={{
            animation: spinning ? 'spin 0.7s linear infinite' : 'none',
          }}
        />
        Refresh
      </button>
    </div>
  )
}
