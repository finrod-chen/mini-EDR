import type { CSSProperties, ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { apiPost } from '../lib/api'

const navLinkStyle = ({ isActive }: { isActive: boolean }): CSSProperties => ({
  padding: '8px 12px',
  textDecoration: 'none',
  color: isActive ? '#fff' : 'inherit',
  background: isActive ? '#333' : 'transparent',
  borderRadius: 4,
})

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
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 20px',
          borderBottom: '1px solid #ddd',
        }}
      >
        <nav style={{ display: 'flex', gap: 8 }}>
          <NavLink to="/alerts" style={navLinkStyle}>
            告警佇列
          </NavLink>
          <NavLink to="/response-actions" style={navLinkStyle}>
            應變紀錄
          </NavLink>
          <NavLink to="/assets" style={navLinkStyle}>
            資產管理
          </NavLink>
        </nav>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {user && (
            <span>
              {user.email}({user.role === 'admin' ? '管理員' : '檢視者'})
            </span>
          )}
          <button onClick={() => void handleLogout()}>登出</button>
        </div>
      </header>
      <main style={{ padding: 20 }}>{children}</main>
    </div>
  )
}
