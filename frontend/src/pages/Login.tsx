import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { loginUrl } from '../lib/api'

export function Login() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="centered-shell">
        <div className="state-message">
          <span className="spinner" />
          載入中…
        </div>
      </div>
    )
  }
  if (user) {
    return <Navigate to="/" replace />
  }

  return (
    <div className="centered-shell">
      <div
        className="card"
        style={{
          padding: '40px 36px',
          textAlign: 'center',
          width: 340,
          animation: 'reveal 320ms cubic-bezier(0.2, 0.7, 0.3, 1)',
        }}
      >
        <h1 style={{ fontSize: '1.75rem' }}>mini-edr</h1>
        <p className="text-muted" style={{ marginBottom: 28 }}>
          內部資產管理 + EDR-like 平台
        </p>
        <a href={loginUrl()} className="btn btn--primary" style={{ width: '100%', padding: '10px 0' }}>
          使用 Google 帳號登入
        </a>
        <p className="text-faint" style={{ marginTop: 20 }}>
          僅限 xiyuebiomed.com.tw 網域帳號
        </p>
      </div>
    </div>
  )
}
