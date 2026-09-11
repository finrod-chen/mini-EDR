import { Fragment, useEffect, useMemo, useState } from 'react'
import { LoadingOverlay } from '../components/LoadingOverlay'
import { apiGet } from '../lib/api'
import type { Asset, Software } from '../lib/types'

type SortKey = 'hostname' | 'monitor_type' | 'ip' | 'os_version' | 'last_seen' | 'health_score'
type SortDir = 'asc' | 'desc'

function compareValues(a: string | number | null, b: string | number | null): number {
  if (a === null && b === null) return 0
  if (a === null) return 1
  if (b === null) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b))
}

function sortValue(asset: Asset, key: SortKey): string | number | null {
  if (key === 'health_score') return asset.health_score
  if (key === 'last_seen') return asset.last_seen ? new Date(asset.last_seen).getTime() : null
  if (key === 'monitor_type') return deviceTypeLabel(asset)
  return asset[key]
}

// 跟 backend app/services/health_score.py 的 KNOWN_EOL_OS_KEYWORDS 保持一致,
// 純粹用來在畫面上標「已過期/正常」,實際扣分邏輯以 backend 算出的
// health_score 為準,這裡沒有重算分數。
const KNOWN_EOL_OS_KEYWORDS = ['windows 7', 'windows 8.1', 'windows 10']

function isEol(osVersion: string | null): boolean {
  if (!osVersion) return false
  const lower = osVersion.toLowerCase()
  return KNOWN_EOL_OS_KEYWORDS.some((keyword) => lower.includes(keyword))
}

// SNMP 監控裝置(印表機/NAS/防火牆)沒有作業系統版本,EOL 這個概念本身
// 對它們不適用——不能直接用 isEol(null) 的結果(會是 false,顯示「正常」),
// 那樣會誤導成「這台裝置的 OS 沒過期」,實際上是「這個判斷根本不適用」。
function deviceTypeLabel(asset: Asset): string {
  if (asset.monitor_type === 'snmp') return asset.device_type ?? 'SNMP'
  return 'Agent'
}

function healthScoreClass(score: number): string {
  if (score >= 80) return 'pill--success'
  if (score >= 50) return ''
  return 'pill--danger'
}

export function AssetManagement() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)
  const [expandedScore, setExpandedScore] = useState<string | null>(null)
  const [software, setSoftware] = useState<Record<string, Software[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('hostname')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  useEffect(() => {
    apiGet<Asset[]>('/api/assets')
      .then(setAssets)
      .catch(() => setError('資產清單載入失敗'))
      .finally(() => setLoading(false))
  }, [])

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const visibleAssets = useMemo(() => {
    const query = search.trim().toLowerCase()
    const filtered = query
      ? assets.filter((asset) =>
          [
            asset.hostname,
            asset.ip,
            asset.os_version,
            asset.vendor,
            asset.model,
            asset.cpu,
            asset.device_type,
            asset.snmp_sys_descr,
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase()
            .includes(query),
        )
      : assets

    const sorted = [...filtered].sort((a, b) => {
      const result = compareValues(sortValue(a, sortKey), sortValue(b, sortKey))
      return sortDir === 'asc' ? result : -result
    })
    return sorted
  }, [assets, search, sortKey, sortDir])

  const sortHeader = (key: SortKey, label: string) => (
    <th className="sortable" onClick={() => toggleSort(key)}>
      {label}
      {sortKey === key && <span className="sort-indicator">{sortDir === 'asc' ? '▲' : '▼'}</span>}
    </th>
  )

  const toggleExpand = (assetId: string, monitorType: Asset['monitor_type']) => {
    if (expanded === assetId) {
      setExpanded(null)
      return
    }
    setExpanded(assetId)
    // SNMP 資產沒有軟體清單概念,不用打這支 API(打了也一定是空陣列)。
    if (monitorType !== 'snmp' && !software[assetId]) {
      apiGet<Software[]>(`/api/assets/${assetId}/software`)
        .then((data) => setSoftware((prev) => ({ ...prev, [assetId]: data })))
        .catch(() => setSoftware((prev) => ({ ...prev, [assetId]: [] })))
    }
  }

  if (error) return <p className="alert-message">{error}</p>

  return (
    <div>
      <div className="page-header">
        <h1>資產管理</h1>
      </div>
      {!loading && assets.length === 0 ? (
        <p className="text-muted">目前沒有資產資料(需要 Phase 1 的 sync_client_roster job 先跑過)。</p>
      ) : (
        <>
          <div className="toolbar">
            <label className="field">
              <span className="field-label">搜尋</span>
              <input
                className="input"
                type="search"
                placeholder="主機名 / IP / 作業系統 / 型號 / CPU"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </label>
          </div>
          {!loading && visibleAssets.length === 0 ? (
            <p className="text-muted">沒有符合搜尋條件的資產。</p>
          ) : (
            <div className={`table-wrap${loading ? ' table-wrap--loading' : ''}`}>
              {loading && <LoadingOverlay />}
              <table className="data-table">
                <thead>
                  <tr>
                    {sortHeader('hostname', '主機名')}
                    {sortHeader('monitor_type', '類型')}
                    {sortHeader('ip', 'IP')}
                    {sortHeader('os_version', '作業系統')}
                    <th>型號 / CPU / RAM</th>
                    <th>EOL</th>
                    {sortHeader('health_score', 'Health Score')}
                    {sortHeader('last_seen', '最後回報')}
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {!loading &&
                    visibleAssets.map((asset) => (
                    <Fragment key={asset.asset_id}>
                      <tr className="row">
                        <td>{asset.hostname ?? '-'}</td>
                        <td>
                          <span className="pill">{deviceTypeLabel(asset)}</span>
                        </td>
                        <td className="text-muted">{asset.ip ?? '-'}</td>
                        <td>{asset.os_version ?? '-'}</td>
                        <td className="text-muted">
                          {[asset.vendor, asset.model, asset.cpu, asset.memory].filter(Boolean).join(' / ') || '-'}
                        </td>
                        <td>
                          {asset.monitor_type === 'snmp' ? (
                            <span className="text-muted">-</span>
                          ) : (
                            <span className={`pill ${isEol(asset.os_version) ? 'pill--danger' : 'pill--success'}`}>
                              {isEol(asset.os_version) ? '已過期' : '正常'}
                            </span>
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className={`pill ${healthScoreClass(asset.health_score)}`}
                            style={{
                              font: 'inherit',
                              fontWeight: 700,
                              cursor: 'pointer',
                              border: 'none',
                              background: 'transparent',
                              padding: 0,
                            }}
                            onClick={() =>
                              setExpandedScore(expandedScore === asset.asset_id ? null : asset.asset_id)
                            }
                          >
                            {asset.health_score}/100 {expandedScore === asset.asset_id ? '▲' : '▼'}
                          </button>
                        </td>
                        <td className="text-muted">
                          {asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '從未回報'}
                        </td>
                        <td>
                          <button
                            className="btn btn--ghost btn--sm"
                            onClick={() => toggleExpand(asset.asset_id, asset.monitor_type)}
                          >
                            {expanded === asset.asset_id
                              ? '收合'
                              : asset.monitor_type === 'snmp'
                                ? 'SNMP 詳細資訊'
                                : '軟體清單'}
                          </button>
                        </td>
                      </tr>
                      {expandedScore === asset.asset_id && (
                        <tr className="detail-row">
                          <td colSpan={9}>
                            <div className="detail-panel">
                              {asset.health_score_breakdown.length === 0 ? (
                                <p className="text-muted">沒有扣分項目,滿分 100。</p>
                              ) : (
                                <>
                                  <p className="text-muted" style={{ marginBottom: 8 }}>
                                    起始 100 分:
                                  </p>
                                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                                    {asset.health_score_breakdown.map((item, i) => (
                                      // eslint-disable-next-line react/no-array-index-key -- 扣分項目沒有唯一 id 可用
                                      <li key={i} className="text-muted">
                                        {item.reason}:−{item.points}
                                      </li>
                                    ))}
                                  </ul>
                                  <p style={{ marginTop: 8, fontWeight: 700 }}>= {asset.health_score}/100</p>
                                </>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                      {expanded === asset.asset_id && (
                        <tr className="detail-row">
                          <td colSpan={9}>
                            <div className="detail-panel">
                              {asset.monitor_type === 'snmp' ? (
                                <dl className="text-muted">
                                  <div>
                                    <strong>sysDescr:</strong> {asset.snmp_sys_descr ?? '-'}
                                  </div>
                                  <div>
                                    <strong>Uptime:</strong>{' '}
                                    {asset.snmp_uptime_seconds != null
                                      ? `${Math.floor(asset.snmp_uptime_seconds / 3600)} 小時`
                                      : '-'}
                                  </div>
                                  <div>
                                    <strong>最後輪詢:</strong>{' '}
                                    {asset.snmp_last_poll_ok === false ? '失敗(裝置離線或無回應)' : '成功'}
                                  </div>
                                </dl>
                              ) : !software[asset.asset_id] ? (
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
        </>
      )}
    </div>
  )
}
