import type { ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { apiPost } from '../lib/api'

export function Layout({ children }: { children: ReactNode }) {
  const { user, refresh } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await apiPost('/auth/logout')
    await refresh()
    navigate('/login')
  }

  return (
    <div>
      <header className="topbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <span className="brand">mini-edr</span>
          <nav className="nav">
            <NavLink to="/alerts" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              告警佇列
            </NavLink>
            <NavLink
              to="/response-actions"
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              應變紀錄
            </NavLink>
            <NavLink to="/assets" className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}>
              資產管理
            </NavLink>
          </nav>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {user && (
            <span className="user-chip">
              <strong>{user.email}</strong> · {user.role === 'admin' ? '管理員' : '檢視者'}
            </span>
          )}
          <button className="btn btn--ghost btn--sm" onClick={() => void handleLogout()}>
            登出
          </button>
        </div>
      </header>
      <main className="page">{children}</main>
    </div>
  )
}
