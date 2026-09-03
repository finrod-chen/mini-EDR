import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { ApiError, apiGet, apiPost } from '../lib/api'
import { SEVERITY_ORDER, severityRank } from '../lib/severity'
import type { ActionType, Alert, ResponseAction, Severity } from '../lib/types'

const STATUS_LABEL: Record<string, string> = {
  open: '未處理',
  acknowledged: '已確認',
  resolved: '已解決',
  false_positive: '誤判',
}

const ACTION_BUTTONS: { type: ActionType; label: string; variant: 'danger' | 'ghost'; confirm?: string }[] = [
  { type: 'quarantine', label: '隔離主機', variant: 'danger', confirm: '確定要隔離這台主機嗎?這會阻斷它的對外網路連線。' },
  { type: 'kill_process', label: '砍進程', variant: 'danger' },
  { type: 'mark_false_positive', label: '標記誤判', variant: 'ghost' },
  { type: 'ignore', label: '忽略', variant: 'ghost' },
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
  const [explainPending, setExplainPending] = useState<string | null>(null)
  const [explainError, setExplainError] = useState<Record<string, string>>({})

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

  const performAction = async (
    alert: Alert,
    actionType: ActionType,
    confirmMessage: string | undefined,
  ) => {
    let pid: number | undefined
    if (actionType === 'kill_process') {
      const input = window.prompt('要砍掉的進程 PID(告警本身沒有記錄觸發的 PID,需要人工確認後手動輸入):')
      if (!input) return
      pid = Number(input)
      if (!Number.isInteger(pid) || pid <= 0) {
        setActionMessage((prev) => ({ ...prev, [alert.alert_id]: 'PID 必須是正整數' }))
        return
      }
      if (!window.confirm(`確定要在 ${alert.host ?? '這台主機'} 上砍掉 PID ${pid} 嗎?此動作無法復原。`)) {
        return
      }
    } else if (confirmMessage && !window.confirm(confirmMessage)) {
      return
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

  const explainAlert = async (alert: Alert) => {
    setExplainPending(alert.alert_id)
    setExplainError((prev) => ({ ...prev, [alert.alert_id]: '' }))
    try {
      const updated = await apiPost<Alert>(`/api/alerts/${alert.alert_id}/explain`)
      setAlerts((prev) => prev.map((a) => (a.alert_id === updated.alert_id ? updated : a)))
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'AI 說明產生失敗'
      setExplainError((prev) => ({ ...prev, [alert.alert_id]: message }))
    } finally {
      setExplainPending(null)
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
        <h1>告警佇列</h1>
      </div>

      <div className="toolbar">
        <label className="field">
          <span className="field-label">Severity</span>
          <select
            className="select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
          >
            <option value="all">全部</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field-label">狀態</span>
          <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
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
        <p className="text-muted">目前沒有符合條件的告警。</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
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
                  <tr className="row">
                    <td>
                      <span className="badge" data-severity={alert.severity ?? 'unknown'}>
                        {alert.severity ?? '未知'}
                      </span>
                    </td>
                    <td>{alert.host ?? '-'}</td>
                    <td>{alert.rule_name ?? '-'}</td>
                    <td className="text-muted">
                      {alert.created_at ? new Date(alert.created_at).toLocaleString() : '-'}
                    </td>
                    <td>{alert.status ? (STATUS_LABEL[alert.status] ?? alert.status) : '-'}</td>
                    <td>
                      <button
                        className="btn btn--ghost btn--sm"
                        onClick={() => setExpanded(expanded === alert.alert_id ? null : alert.alert_id)}
                      >
                        {expanded === alert.alert_id ? '收合' : '詳情'}
                      </button>
                    </td>
                  </tr>
                  {expanded === alert.alert_id && (
                    <tr className="detail-row">
                      <td colSpan={6}>
                        <div className="detail-panel">
                          <p style={{ marginBottom: 8 }}>
                            <strong>AI 說明:</strong> {alert.ai_explanation ?? '尚未產生'}
                          </p>
                          <div className="btn-row" style={{ alignItems: 'center', marginBottom: 12 }}>
                            <button
                              className="btn btn--sm"
                              disabled={explainPending === alert.alert_id}
                              onClick={() => void explainAlert(alert)}
                            >
                              {alert.ai_explanation ? '重新產生 AI 說明' : '產生 AI 說明'}
                            </button>
                            {explainError[alert.alert_id] && (
                              <span className="alert-message">{explainError[alert.alert_id]}</span>
                            )}
                          </div>
                          <p className="text-faint" style={{ marginBottom: 12 }}>
                            進程鏈需要額外一支關聯查詢 API(依主機+時間比對 process_events),目前告警 API
                            還沒提供,先不顯示假資料。
                          </p>
                          {user?.role === 'admin' && (
                            <div>
                              <div className="btn-row">
                                {ACTION_BUTTONS.map(({ type, label, variant, confirm }) => (
                                  <button
                                    key={type}
                                    className={`btn btn--sm btn--${variant}`}
                                    disabled={actionPending === alert.alert_id}
                                    onClick={() => void performAction(alert, type, confirm)}
                                  >
                                    {label}
                                  </button>
                                ))}
                              </div>
                              {actionMessage[alert.alert_id] && (
                                <p className="text-muted" style={{ marginTop: 8 }}>
                                  {actionMessage[alert.alert_id]}
                                </p>
                              )}
                            </div>
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
