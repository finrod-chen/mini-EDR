import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { ApiError, apiGet, apiPost } from '../lib/api'
import { SEVERITY_COLOR, SEVERITY_ORDER, severityRank } from '../lib/severity'
import type { ActionType, Alert, ResponseAction, Severity } from '../lib/types'

const STATUS_LABEL: Record<string, string> = {
  open: '未處理',
  acknowledged: '已確認',
  resolved: '已解決',
  false_positive: '誤判',
}

const ACTION_BUTTONS: { type: ActionType; label: string }[] = [
  { type: 'quarantine', label: '隔離主機' },
  { type: 'kill_process', label: '砍進程' },
  { type: 'mark_false_positive', label: '標記誤判' },
  { type: 'ignore', label: '忽略' },
]

export function AlertQueue() {
  const { user } = useAuth()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [actionPending, setActionPending] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<Record<string, string>>({})

  const loadAlerts = useCallback(() => {
    setLoading(true)
    return apiGet<Alert[]>('/api/alerts', {
      severity: severityFilter === 'all' ? undefined : severityFilter,
      status: statusFilter === 'all' ? undefined : statusFilter,
    })
      .then((data) => setAlerts(data))
      .catch(() => setError('告警清單載入失敗'))
      .finally(() => setLoading(false))
  }, [severityFilter, statusFilter])

  useEffect(() => {
    void loadAlerts()
  }, [loadAlerts])

  const sortedAlerts = useMemo(
    () => [...alerts].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [alerts],
  )

  const performAction = async (alert: Alert, actionType: ActionType) => {
    let pid: number | undefined
    if (actionType === 'kill_process') {
      const input = window.prompt('要砍掉的進程 PID(告警本身沒有記錄觸發的 PID,需要人工確認後手動輸入):')
      if (!input) return
      pid = Number(input)
      if (!Number.isInteger(pid) || pid <= 0) {
        setActionMessage((prev) => ({ ...prev, [alert.alert_id]: 'PID 必須是正整數' }))
        return
      }
    }

    setActionPending(alert.alert_id)
    setActionMessage((prev) => ({ ...prev, [alert.alert_id]: '' }))
    try {
      const action = await apiPost<ResponseAction>(`/api/alerts/${alert.alert_id}/actions`, {
        action_type: actionType,
        pid,
      })
      const message = action.result?.startsWith('failed:') ? action.result : '執行成功'
      setActionMessage((prev) => ({ ...prev, [alert.alert_id]: message }))
      await loadAlerts()
    } catch (err) {
      const message = err instanceof ApiError ? err.message : '執行失敗'
      setActionMessage((prev) => ({ ...prev, [alert.alert_id]: message }))
    } finally {
      setActionPending(null)
    }
  }

  if (loading) return <p>載入中…</p>
  if (error) return <p>{error}</p>

  return (
    <div>
      <h1>告警佇列</h1>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <label>
          Severity:{' '}
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}>
            <option value="all">全部</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label>
          狀態:{' '}
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="all">全部</option>
            {Object.entries(STATUS_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {sortedAlerts.length === 0 ? (
        <p>目前沒有符合條件的告警。</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '2px solid #ddd' }}>
              <th>Severity</th>
              <th>主機</th>
              <th>規則名稱</th>
              <th>觸發時間</th>
              <th>狀態</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sortedAlerts.map((alert) => (
              <Fragment key={alert.alert_id}>
                <tr style={{ borderBottom: '1px solid #eee' }}>
                  <td>
                    <span
                      style={{
                        color: '#fff',
                        background: alert.severity ? SEVERITY_COLOR[alert.severity] : '#888',
                        padding: '2px 8px',
                        borderRadius: 4,
                        fontSize: 12,
                      }}
                    >
                      {alert.severity ?? '未知'}
                    </span>
                  </td>
                  <td>{alert.host ?? '-'}</td>
                  <td>{alert.rule_name ?? '-'}</td>
                  <td>{alert.created_at ? new Date(alert.created_at).toLocaleString() : '-'}</td>
                  <td>{alert.status ? (STATUS_LABEL[alert.status] ?? alert.status) : '-'}</td>
                  <td>
                    <button
                      onClick={() => setExpanded(expanded === alert.alert_id ? null : alert.alert_id)}
                    >
                      {expanded === alert.alert_id ? '收合' : '詳情'}
                    </button>
                  </td>
                </tr>
                {expanded === alert.alert_id && (
                  <tr>
                    <td colSpan={6} style={{ background: '#fafafa', padding: 16 }}>
                      <p>
                        <strong>AI 說明:</strong> {alert.ai_explanation ?? '尚未產生(Phase 6 選配功能)'}
                      </p>
                      <p style={{ color: '#888' }}>
                        進程鏈需要額外一支關聯查詢 API(依主機+時間比對
                        process_events),目前告警 API 還沒提供,先不顯示假資料。
                      </p>
                      {user?.role === 'admin' && (
                        <div>
                          <div style={{ display: 'flex', gap: 8 }}>
                            {ACTION_BUTTONS.map(({ type, label }) => (
                              <button
                                key={type}
                                disabled={actionPending === alert.alert_id}
                                onClick={() => void performAction(alert, type)}
                              >
                                {label}
                              </button>
                            ))}
                          </div>
                          {actionMessage[alert.alert_id] && (
                            <p style={{ marginTop: 8, color: '#888' }}>{actionMessage[alert.alert_id]}</p>
                          )}
                        </div>
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
