import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { loginUrl } from '../lib/api'

export function Login() {
  const { user, loading } = useAuth()

  if (loading) {
    return <p>載入中…</p>
  }
  if (user) {
    return <Navigate to="/" replace />
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: '20vh' }}>
      <h1>mini-edr</h1>
      <p>內部資產管理 + EDR-like 平台</p>
      <a
        href={loginUrl()}
        style={{
          marginTop: 24,
          padding: '10px 20px',
          border: '1px solid #ccc',
          borderRadius: 6,
          textDecoration: 'none',
          color: 'inherit',
        }}
      >
        使用 Google 帳號登入
      </a>
    </div>
  )
}
