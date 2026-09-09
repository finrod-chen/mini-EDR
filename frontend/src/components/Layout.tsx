import type { ReactNode } from 'react'
import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { apiPost } from '../lib/api'
import { Logo } from './Logo'

const NAV_ITEMS = [
  { to: '/alerts', label: '告警佇列' },
  { to: '/response-actions', label: '應變紀錄' },
  { to: '/assets', label: '資產管理' },
]

export function Layout({ children }: { children: ReactNode }) {
  const { user, refresh } = useAuth()
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const handleLogout = async () => {
    await apiPost('/auth/logout')
    await refresh()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />}

      <aside className={`sidebar${sidebarOpen ? ' sidebar--open' : ''}`}>
        <div className="sidebar-brand">
          <Logo />
          <span className="brand">mini-edr</span>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
              onClick={() => setSidebarOpen(false)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div className="user-chip">
              <strong>{user.email}</strong>
              <span className="text-faint">{user.role === 'admin' ? '管理員' : '檢視者'}</span>
            </div>
          )}
          <button className="btn btn--outline btn--sm" onClick={() => void handleLogout()}>
            登出
          </button>
        </div>
      </aside>

      <div className="app-content">
        <header className="mobile-topbar">
          <button
            className="btn btn--ghost btn--sm"
            aria-label="開啟選單"
            onClick={() => setSidebarOpen(true)}
          >
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path
                d="M2 4.5H16M2 9H16M2 13.5H16"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            </svg>
          </button>
          <div className="sidebar-brand">
            <Logo size={22} />
            <span className="brand">mini-edr</span>
          </div>
        </header>
        <main className="page">{children}</main>
      </div>
    </div>
  )
}
