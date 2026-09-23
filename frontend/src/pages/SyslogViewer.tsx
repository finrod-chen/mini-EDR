import { Fragment, useCallback, useEffect, useState } from 'react'
import { LoadingOverlay } from '../components/LoadingOverlay'
import { apiGet } from '../lib/api'
import type { SyslogMessage, SyslogSourceType } from '../lib/types'

const SOURCE_TYPE_LABEL: Record<SyslogSourceType, string> = {
  pan410: 'PA-410',
  synology_nas: 'Synology NAS',
  other: '其他',
}

// 原始內容單行顯示會被截斷(見下面 .text-truncate),超過這個長度才值得
// 給「詳情」按鈕——太短的內容展開跟不展開看起來沒差,不用多一個互動。
const TRUNCATE_THRESHOLD = 80

export function SyslogViewer() {
  const [messages, setMessages] = useState<SyslogMessage[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [sourceType, setSourceType] = useState<SyslogSourceType | 'all'>('all')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    return apiGet<SyslogMessage[]>('/api/syslog', {
      source_type: sourceType === 'all' ? undefined : sourceType,
      q: search.trim() || undefined,
    })
      .then(setMessages)
      .catch(() => setError('Syslog 記錄載入失敗'))
      .finally(() => setLoading(false))
  }, [sourceType, search])

  useEffect(() => {
    // 搜尋文字打字時不用每個按鍵都打 API,等使用者停下來一下再查——跟
    // AlertQueue 的篩選器不同(那些是下拉選單,選了就該立刻查),這裡是
    // 自由輸入的文字框。
    const timer = setTimeout(() => void load(), 300)
    return () => clearTimeout(timer)
  }, [load])

  return (
    <div>
      <div className="page-header">
        <h1>Syslog 記錄</h1>
        <p className="text-muted">
          PA-410 防火牆與 Synology NAS 送進來的原始 syslog,不管有沒有觸發告警都存在這裡,保留 30 天。
        </p>
      </div>

      <div className="toolbar">
        <label className="field">
          <span className="field-label">來源</span>
          <select
            className="select"
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value as SyslogSourceType | 'all')}
          >
            <option value="all">全部</option>
            <option value="pan410">PA-410</option>
            <option value="synology_nas">Synology NAS</option>
            <option value="other">其他</option>
          </select>
        </label>
        <label className="field">
          <span className="field-label">搜尋</span>
          <input
            className="input"
            type="search"
            placeholder="原始內容關鍵字"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
      </div>

      {error && <p className="alert-message">{error}</p>}
      {!error && !loading && messages.length === 0 && (
        <p className="text-muted">沒有符合條件的 syslog 記錄。</p>
      )}
      {!error && (loading || messages.length > 0) && (
        <div className={`table-wrap${loading ? ' table-wrap--loading' : ''}`}>
          {loading && <LoadingOverlay />}
          <table className="data-table">
            <thead>
              <tr>
                <th>時間</th>
                <th>來源 IP</th>
                <th>來源</th>
                <th>原始內容</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {!loading &&
                messages.map((msg) => {
                  const raw = msg.raw_message ?? ''
                  const isLong = raw.length > TRUNCATE_THRESHOLD
                  return (
                    <Fragment key={msg.id}>
                      <tr className="row">
                        <td className="text-muted">
                          {msg.received_at ? new Date(msg.received_at).toLocaleString() : '-'}
                        </td>
                        <td>{msg.source_ip ?? '-'}</td>
                        <td>
                          <span className="pill">
                            {msg.source_type ? SOURCE_TYPE_LABEL[msg.source_type] : '未知'}
                          </span>
                        </td>
                        <td className="text-truncate" style={{ maxWidth: 480 }}>
                          {raw || '-'}
                        </td>
                        <td>
                          {isLong && (
                            <button
                              className="btn btn--ghost btn--sm"
                              onClick={() => setExpanded(expanded === msg.id ? null : msg.id)}
                            >
                              {expanded === msg.id ? '收合' : '詳情'}
                            </button>
                          )}
                        </td>
                      </tr>
                      {expanded === msg.id && (
                        <tr className="detail-row">
                          <td colSpan={5}>
                            <div className="detail-panel">
                              <p style={{ margin: 0, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
                                {raw}
                              </p>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
