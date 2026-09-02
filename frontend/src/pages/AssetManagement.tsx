import { Fragment, useEffect, useState } from 'react'
import { apiGet } from '../lib/api'
import type { Asset, Software } from '../lib/types'

// 跟 backend app/services/health_score.py 的 KNOWN_EOL_OS_KEYWORDS 保持一致,
// 純粹用來在畫面上標「已過期/正常」,實際扣分邏輯以 backend 算出的
// health_score 為準,這裡沒有重算分數。
const KNOWN_EOL_OS_KEYWORDS = ['windows 7', 'windows 8.1', 'windows 10']

function isEol(osVersion: string | null): boolean {
  if (!osVersion) return false
  const lower = osVersion.toLowerCase()
  return KNOWN_EOL_OS_KEYWORDS.some((keyword) => lower.includes(keyword))
}

function healthScoreColor(score: number): string {
  if (score >= 80) return '#15803d'
  if (score >= 50) return '#b45309'
  return '#b91c1c'
}

export function AssetManagement() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [software, setSoftware] = useState<Record<string, Software[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    apiGet<Asset[]>('/api/assets')
      .then(setAssets)
      .catch(() => setError('資產清單載入失敗'))
      .finally(() => setLoading(false))
  }, [])

  const toggleExpand = (assetId: string) => {
    if (expanded === assetId) {
      setExpanded(null)
      return
    }
    setExpanded(assetId)
    if (!software[assetId]) {
      apiGet<Software[]>(`/api/assets/${assetId}/software`)
        .then((data) => setSoftware((prev) => ({ ...prev, [assetId]: data })))
        .catch(() => setSoftware((prev) => ({ ...prev, [assetId]: [] })))
    }
  }

  if (loading) return <p>載入中…</p>
  if (error) return <p>{error}</p>

  return (
    <div>
      <h1>資產管理</h1>
      {assets.length === 0 ? (
        <p>目前沒有資產資料(需要 Phase 1 的 sync_client_roster job 先跑過)。</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '2px solid #ddd' }}>
              <th>主機名</th>
              <th>IP</th>
              <th>作業系統</th>
              <th>型號 / CPU / RAM</th>
              <th>EOL</th>
              <th>Health Score</th>
              <th>最後回報</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => (
              <Fragment key={asset.asset_id}>
                <tr style={{ borderBottom: '1px solid #eee' }}>
                  <td>{asset.hostname ?? '-'}</td>
                  <td>{asset.ip ?? '-'}</td>
                  <td>{asset.os_version ?? '-'}</td>
                  <td>
                    {[asset.vendor, asset.model, asset.cpu, asset.memory].filter(Boolean).join(' / ') || '-'}
                  </td>
                  <td>
                    {isEol(asset.os_version) ? (
                      <span style={{ color: '#b91c1c' }}>已過期</span>
                    ) : (
                      <span style={{ color: '#15803d' }}>正常</span>
                    )}
                  </td>
                  <td style={{ color: healthScoreColor(asset.health_score), fontWeight: 'bold' }}>
                    {asset.health_score}/100
                  </td>
                  <td>{asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '從未回報'}</td>
                  <td>
                    <button onClick={() => toggleExpand(asset.asset_id)}>
                      {expanded === asset.asset_id ? '收合' : '軟體清單'}
                    </button>
                  </td>
                </tr>
                {expanded === asset.asset_id && (
                  <tr>
                    <td colSpan={8} style={{ background: '#fafafa', padding: 16 }}>
                      {!software[asset.asset_id] ? (
                        <p>載入中…</p>
                      ) : software[asset.asset_id].length === 0 ? (
                        <p>沒有軟體安裝紀錄。</p>
                      ) : (
                        <table style={{ width: '100%' }}>
                          <thead>
                            <tr style={{ textAlign: 'left' }}>
                              <th>軟體名稱</th>
                              <th>版本</th>
                              <th>發布商</th>
                              <th>安裝時間</th>
                            </tr>
                          </thead>
                          <tbody>
                            {software[asset.asset_id].map((sw, i) => (
                              // eslint-disable-next-line react/no-array-index-key -- software_inventory 沒有唯一 id 可用
                              <tr key={i}>
                                <td>{sw.software_name ?? '-'}</td>
                                <td>{sw.version ?? '-'}</td>
                                <td>{sw.publisher ?? '-'}</td>
                                <td>{sw.install_date ? new Date(sw.install_date).toLocaleDateString() : '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
