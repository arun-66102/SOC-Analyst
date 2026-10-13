import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Bell, GitBranch, Shield, FileText, Activity,
  ChevronRight, Menu, X, Cpu
} from 'lucide-react'
import { getHealth } from './api'

// Pages
import Overview     from './pages/Overview'
import AlertsPage   from './pages/AlertsPage'
import AlertDetail  from './pages/AlertDetail'
import Incidents    from './pages/Incidents'
import MitrePage    from './pages/MitrePage'
import Reports      from './pages/Reports'
import Analyze      from './pages/Analyze'

const NAV = [
  { to: '/',          icon: LayoutDashboard, label: 'Overview' },
  { to: '/alerts',    icon: Bell,            label: 'Alerts' },
  { to: '/incidents', icon: GitBranch,       label: 'Incidents' },
  { to: '/mitre',     icon: Shield,          label: 'MITRE ATT&CK' },
  { to: '/reports',   icon: FileText,        label: 'Reports' },
  { to: '/analyze',   icon: Cpu,             label: 'Analyze' },
]

function Sidebar({ open, setOpen }) {
  const [apiOnline, setApiOnline] = useState(null)

  useEffect(() => {
    const check = () => getHealth()
      .then(() => setApiOnline(true))
      .catch(() => setApiOnline(false))
    check()
    const t = setInterval(check, 30000)
    return () => clearInterval(t)
  }, [])

  return (
    <>
      {/* Mobile overlay */}
      {open && (
        <div
          className="sidebar-overlay"
          onClick={() => setOpen(false)}
        />
      )}

      <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}>
        {/* Logo */}
        <div className="sidebar-logo">
          <div className="logo-icon">
            <Activity size={18} color="var(--accent-blue)" />
          </div>
          <div className="logo-text">
            <span className="logo-main">SOC Analyst</span>
            <span className="logo-sub">AI-Powered</span>
          </div>
          <button className="sidebar-close-btn" onClick={() => setOpen(false)}>
            <X size={16} />
          </button>
        </div>

        {/* API Status */}
        <div className="sidebar-status">
          <span
            className={`status-dot ${apiOnline === null ? 'warn' : apiOnline ? 'live' : 'error'}`}
          />
          <span className="status-label">
            {apiOnline === null ? 'Connecting…' : apiOnline ? 'API Online' : 'API Offline'}
          </span>
        </div>

        {/* Navigation */}
        <nav className="sidebar-nav">
          <span className="section-title" style={{ padding: '0 12px' }}>Navigation</span>
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'nav-item-active' : ''}`}
              onClick={() => setOpen(false)}
            >
              <Icon size={16} />
              <span>{label}</span>
              <ChevronRight size={12} className="nav-chevron" />
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="sidebar-footer">
          <span className="sidebar-footer-text">v0.3.0 — Phase 3 Complete</span>
        </div>
      </aside>
    </>
  )
}

function TopBar({ setOpen }) {
  const location = useLocation()
  const current = NAV.find(n => n.to === location.pathname) || { label: 'SOC Analyst' }
  const [time, setTime] = useState(new Date())

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button className="topbar-menu-btn" onClick={() => setOpen(v => !v)}>
          <Menu size={18} />
        </button>
        <span className="topbar-title">{current.label}</span>
      </div>
      <div className="topbar-right">
        <span className="topbar-time mono">{time.toLocaleTimeString('en-US', { hour12: false })}</span>
        <span className="topbar-date">{time.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</span>
      </div>
    </header>
  )
}

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar open={sidebarOpen} setOpen={setSidebarOpen} />
        <div className="main-area">
          <TopBar setOpen={setSidebarOpen} />
          <main className="page-content">
            <Routes>
              <Route path="/"            element={<Overview />} />
              <Route path="/alerts"      element={<AlertsPage />} />
              <Route path="/alerts/:id"  element={<AlertDetail />} />
              <Route path="/incidents"   element={<Incidents />} />
              <Route path="/mitre"       element={<MitrePage />} />
              <Route path="/reports"     element={<Reports />} />
              <Route path="/analyze"     element={<Analyze />} />
            </Routes>
          </main>
        </div>
      </div>

      <style>{`
        .app-layout {
          display: flex;
          min-height: 100vh;
          background: var(--bg-base);
        }

        /* ── Sidebar ── */
        .sidebar {
          width: 220px;
          min-width: 220px;
          background: var(--bg-surface);
          border-right: 1px solid var(--border-subtle);
          display: flex;
          flex-direction: column;
          position: fixed;
          top: 0; left: 0; bottom: 0;
          z-index: 100;
          transition: transform 0.25s ease;
        }
        .sidebar-overlay {
          position: fixed; inset: 0;
          background: rgba(0,0,0,0.5);
          z-index: 99;
          display: none;
        }
        .sidebar-logo {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 18px 16px;
          border-bottom: 1px solid var(--border-subtle);
        }
        .logo-icon {
          width: 32px; height: 32px;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: 8px;
          display: flex; align-items: center; justify-content: center;
          flex-shrink: 0;
        }
        .logo-text { flex: 1; }
        .logo-main { display: block; font-size: 0.92rem; font-weight: 800; color: var(--text-primary); line-height: 1.2; letter-spacing: -0.01em; }
        .logo-sub  { display: block; font-size: 0.65rem; color: var(--accent-blue); letter-spacing: 0.08em; text-transform: uppercase; font-weight: 700; }
        .sidebar-close-btn {
          display: none;
          background: none; border: none; cursor: pointer;
          color: var(--text-muted); padding: 4px;
        }
        .sidebar-status {
          display: flex; align-items: center; gap: 8px;
          padding: 10px 16px;
          border-bottom: 1px solid var(--border-subtle);
          font-size: 0.75rem;
          color: var(--text-muted);
          background: #f8fafc;
        }
        .status-label { font-size: 0.72rem; font-weight: 500; }
        .sidebar-nav {
          flex: 1; overflow-y: auto;
          padding: 12px 8px;
          display: flex; flex-direction: column; gap: 3px;
        }
        .nav-item {
          display: flex; align-items: center; gap: 10px;
          padding: 9px 12px;
          border-radius: 8px;
          text-decoration: none;
          color: var(--text-secondary);
          font-size: 0.85rem;
          font-weight: 500;
          transition: all 0.15s;
          position: relative;
        }
        .nav-item:hover { background: var(--bg-elevated); color: var(--text-primary); }
        .nav-item-active {
          background: #eff6ff !important;
          color: var(--accent-blue) !important;
          border: 1px solid #bfdbfe;
          font-weight: 600;
        }
        .nav-chevron { margin-left: auto; opacity: 0; transition: opacity 0.15s; }
        .nav-item-active .nav-chevron, .nav-item:hover .nav-chevron { opacity: 0.7; }
        .sidebar-footer {
          padding: 12px 16px;
          border-top: 1px solid var(--border-subtle);
          background: #f8fafc;
        }
        .sidebar-footer-text { font-size: 0.68rem; color: var(--text-muted); font-weight: 500; }

        /* ── Main area ── */
        .main-area {
          flex: 1;
          margin-left: 220px;
          display: flex; flex-direction: column;
          min-height: 100vh;
        }
        .topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 0 24px;
          height: 52px;
          background: var(--bg-surface);
          border-bottom: 1px solid var(--border-subtle);
          box-shadow: 0 1px 2px 0 rgba(15, 23, 42, 0.03);
          position: sticky; top: 0; z-index: 50;
        }
        .topbar-left { display: flex; align-items: center; gap: 12px; }
        .topbar-menu-btn {
          display: none;
          background: none; border: none; cursor: pointer;
          color: var(--text-muted); padding: 4px;
        }
        .topbar-title { font-size: 0.95rem; font-weight: 700; color: var(--text-primary); }
        .topbar-right { display: flex; align-items: center; gap: 16px; }
        .topbar-time { font-size: 0.85rem; color: var(--accent-blue); font-weight: 700; }
        .topbar-date { font-size: 0.78rem; color: var(--text-muted); }
        .page-content {
          flex: 1;
          padding: 24px;
          overflow-y: auto;
          animation: fade-in 0.3s ease;
        }

        /* ── Responsive ── */
        @media (max-width: 768px) {
          .sidebar { transform: translateX(-100%); }
          .sidebar-open { transform: translateX(0); }
          .sidebar-overlay { display: block; }
          .sidebar-close-btn { display: flex; }
          .main-area { margin-left: 0; }
          .topbar-menu-btn { display: flex; }
        }
      `}</style>
    </BrowserRouter>
  )
}
