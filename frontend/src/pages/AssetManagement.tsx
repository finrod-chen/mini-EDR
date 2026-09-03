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

function healthScoreClass(score: number): string {
  if (score >= 80) return 'pill--success'
  if (score >= 50) return ''
  return 'pill--danger'
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

  if (loading) {
    return (
      <div className="state-message">
        <span className="spinner" />
        載入中…
      </div>
    )
  }
  if (error) return <p className="alert-message">{error}</p>

  return (
    <div>
      <div className="page-header">
        <h1>資產管理</h1>
      </div>
      {assets.length === 0 ? (
        <p className="text-muted">目前沒有資產資料(需要 Phase 1 的 sync_client_roster job 先跑過)。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
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
                  <tr className="row">
                    <td>{asset.hostname ?? '-'}</td>
                    <td className="text-muted">{asset.ip ?? '-'}</td>
                    <td>{asset.os_version ?? '-'}</td>
                    <td className="text-muted">
                      {[asset.vendor, asset.model, asset.cpu, asset.memory].filter(Boolean).join(' / ') || '-'}
                    </td>
                    <td>
                      <span className={`pill ${isEol(asset.os_version) ? 'pill--danger' : 'pill--success'}`}>
                        {isEol(asset.os_version) ? '已過期' : '正常'}
                      </span>
                    </td>
                    <td>
                      <span className={`pill ${healthScoreClass(asset.health_score)}`} style={{ fontWeight: 700 }}>
                        {asset.health_score}/100
                      </span>
                    </td>
                    <td className="text-muted">
                      {asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '從未回報'}
                    </td>
                    <td>
                      <button className="btn btn--ghost btn--sm" onClick={() => toggleExpand(asset.asset_id)}>
                        {expanded === asset.asset_id ? '收合' : '軟體清單'}
                      </button>
                    </td>
                  </tr>
                  {expanded === asset.asset_id && (
                    <tr className="detail-row">
                      <td colSpan={8}>
                        <div className="detail-panel">
                          {!software[asset.asset_id] ? (
                            <div className="state-message" style={{ padding: 0 }}>
                              <span className="spinner" />
                              載入中…
                            </div>
                          ) : software[asset.asset_id].length === 0 ? (
                            <p className="text-muted">沒有軟體安裝紀錄。</p>
                          ) : (
                            <table className="data-table">
                              <thead>
                                <tr>
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
                                    <td>
                                      {sw.install_date ? new Date(sw.install_date).toLocaleDateString() : '-'}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
