/**
 * components/LoadingSpinner.jsx
 * -----------------------------
 * Centered loading spinner with optional message.
 *
 * Props:
 *   size    — number  (default 28, spinner px size)
 *   padding — number  (default 64, wrapper padding in px)
 *   message — string  (optional label below spinner)
 */

export default function LoadingSpinner({ size = 28, padding = 64, message }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding,
        gap: 12,
      }}
    >
      <div className="spinner" style={{ width: size, height: size }} />
      {message && (
        <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>{message}</p>
      )}
    </div>
  )
}
