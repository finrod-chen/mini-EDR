import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { LoadingOverlay } from '../components/LoadingOverlay'
import { ApiError, apiGet, apiPost } from '../lib/api'
import { useAssetIpLookup } from '../lib/assetLookup'
import type { BlockedIp } from '../lib/types'

function formatTimeout(seconds: number | null): string {
  if (seconds === null) return '永久(或已轉為 persistent,需要到 PAN-OS 手動處理)'
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (hours > 0) return `約 ${hours} 小時後自動解除`
  return `約 ${minutes} 分鐘後自動解除`
}

export function FirewallBlocklist() {
  const { user } = useAuth()
  const assetLookup = useAssetIpLookup()
  const [ips, setIps] = useState<BlockedIp[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState<string | null>(null)
  const [message, setMessage] = useState<Record<string, string>>({})

  const loadBlockedIps = useCallback(() => {
    setLoading(true)
    setError(null)
    return apiGet<BlockedIp[]>('/api/firewall/blocked-ips')
      .then((data) => setIps(data))
      .catch(() => setError('封鎖清單載入失敗,請確認 PAN-OS API 連線是否正常。'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    void loadBlockedIps()
  }, [loadBlockedIps])

  const unblock = async (ip: string) => {
    if (!window.confirm(`確定要解除封鎖 ${ip} 嗎?此動作會透過 PAN-OS User-ID API 立即生效。`)) return
    setPending(ip)
    setMessage((prev) => ({ ...prev, [ip]: '' }))
    try {
      await apiPost('/api/firewall/blocked-ips/unblock', { ip })
      await loadBlockedIps()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : '解除封鎖失敗'
      setMessage((prev) => ({ ...prev, [ip]: msg }))
    } finally {
      setPending(null)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>防火牆封鎖清單</h1>
        <p className="text-muted">目前透過 PAN-OS User-ID API 打上封鎖 tag 的來源 IP。</p>
      </div>

      {error && <p className="alert-message">{error}</p>}
      {!error && !loading && ips.length === 0 && <p className="text-muted">目前沒有被封鎖的 IP。</p>}
      {!error && (loading || ips.length > 0) && (
        <div className={`table-wrap${loading ? ' table-wrap--loading' : ''}`}>
          {loading && <LoadingOverlay />}
          <table className="data-table">
            <thead>
              <tr>
                <th>來源 IP</th>
                <th>Tag</th>
                <th>自動解除時間</th>
                {user?.role === 'admin' && <th />}
              </tr>
            </thead>
            <tbody>
              {!loading &&
                ips.map((row) => (
                  <tr className="row" key={row.ip}>
                    <td>
                      {assetLookup.has(row.ip) ? (
                        <>
                          {assetLookup.get(row.ip)}
                          <div className="text-faint">{row.ip}</div>
                        </>
                      ) : (
                        row.ip
                      )}
                    </td>
                    <td className="text-muted">{row.tag}</td>
                    <td className="text-muted">{formatTimeout(row.timeout_seconds)}</td>
                    {user?.role === 'admin' && (
                      <td>
                        <div className="btn-row" style={{ alignItems: 'center' }}>
                          <button
                            className="btn btn--sm btn--danger"
                            disabled={pending === row.ip}
                            onClick={() => void unblock(row.ip)}
                          >
                            解除封鎖
                          </button>
                          {message[row.ip] && <span className="text-muted">{message[row.ip]}</span>}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
