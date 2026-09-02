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
      <h1>應變紀錄</h1>
      <p style={{ color: '#888' }}>
        對應 ISO 27001 事件應變稽核佐證。目前會是空的,因為隔離主機/砍進程等實際執行邏輯是 Phase 5
        才串接 Velociraptor API。
      </p>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'end' }}>
        <label>
          起始時間
          <br />
          <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
        </label>
        <label>
          結束時間
          <br />
          <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
        </label>
        <button disabled={actions.length === 0} onClick={() => downloadCsv(actions)}>
          匯出 CSV
        </button>
      </div>

      {loading && <p>載入中…</p>}
      {error && <p>{error}</p>}
      {!loading && !error && actions.length === 0 && <p>目前沒有應變紀錄。</p>}
      {!loading && !error && actions.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '2px solid #ddd' }}>
              <th>時間</th>
              <th>操作者</th>
              <th>動作類型</th>
              <th>目標主機</th>
              <th>結果</th>
            </tr>
          </thead>
          <tbody>
            {actions.map((action) => (
              <tr key={action.action_id} style={{ borderBottom: '1px solid #eee' }}>
                <td>{action.performed_at ? new Date(action.performed_at).toLocaleString() : '-'}</td>
                <td>{action.performed_by ?? '-'}</td>
                <td>{action.action_type ?? '-'}</td>
                <td>{action.host ?? '-'}</td>
                <td>{action.result ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
