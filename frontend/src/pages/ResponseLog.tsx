import { useEffect, useState } from 'react'
import { apiGet } from '../lib/api'
import type { ResponseAction } from '../lib/types'

function toCsv(rows: ResponseAction[]): string {
  const header = ['時間', '操作者', '動作類型', '目標主機', '結果']
  const lines = rows.map((row) =>
    [row.performed_at ?? '', row.performed_by ?? '', row.action_type ?? '', row.host ?? '', row.result ?? '']
      .map((value) => `"${String(value).replace(/"/g, '""')}"`)
      .join(','),
  )
  return [header.join(','), ...lines].join('\n')
}

function downloadCsv(rows: ResponseAction[]) {
  const blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `response-actions-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
}

export function ResponseLog() {
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    apiGet<ResponseAction[]>('/api/response-actions', {
      since: since || undefined,
      until: until || undefined,
    })
      .then((data) => {
        if (!cancelled) setActions(data)
      })
      .catch(() => {
        if (!cancelled) setError('應變紀錄載入失敗')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [since, until])

  return (
    <div>
      <div className="page-header">
        <h1>應變紀錄</h1>
        <p className="text-muted">對應 ISO 27001 事件應變稽核佐證。</p>
      </div>

      <div className="toolbar">
        <label className="field">
          <span className="field-label">起始時間</span>
          <input
            className="input"
            type="datetime-local"
            value={since}
            onChange={(e) => setSince(e.target.value)}
          />
        </label>
        <label className="field">
          <span className="field-label">結束時間</span>
          <input
            className="input"
            type="datetime-local"
            value={until}
            onChange={(e) => setUntil(e.target.value)}
          />
        </label>
        <button className="btn" disabled={actions.length === 0} onClick={() => downloadCsv(actions)}>
          匯出 CSV
        </button>
      </div>

      {loading && (
        <div className="state-message">
          <span className="spinner" />
          載入中…
        </div>
      )}
      {error && <p className="alert-message">{error}</p>}
      {!loading && !error && actions.length === 0 && <p className="text-muted">目前沒有應變紀錄。</p>}
      {!loading && !error && actions.length > 0 && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>時間</th>
                <th>操作者</th>
                <th>動作類型</th>
                <th>目標主機</th>
                <th>結果</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((action) => (
                <tr className="row" key={action.action_id}>
                  <td className="text-muted">
                    {action.performed_at ? new Date(action.performed_at).toLocaleString() : '-'}
                  </td>
                  <td>{action.performed_by ?? '-'}</td>
                  <td>{action.action_type ?? '-'}</td>
                  <td>{action.host ?? '-'}</td>
                  <td>{action.result ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
