import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { LoadingOverlay } from '../components/LoadingOverlay'
import { ApiError, apiGet, apiPost } from '../lib/api'
import { SEVERITY_ORDER, severityRank } from '../lib/severity'
import type {
  ActionType,
  Alert,
  FileClassification,
  RelatedProcessEvent,
  ResponseAction,
  Severity,
} from '../lib/types'

const STATUS_LABEL: Record<string, string> = {
  open: '未處理',
  acknowledged: '已確認',
  resolved: '已解決',
  false_positive: '誤判',
}

// 高風險、不容易復原的動作(danger,實心紅)跟單純改狀態的安全動作分開
// 兩組,畫面上也用間距隔開,降低危險動作被按錯的機率(見 AlertQueue 詳情頁
// 的按鈕排版)。安全動作彼此也給不同實色(primary 深藍/success 深綠),
// 不共用同一個中性色,一眼就能分辨點的是哪一個。
const HIGH_RISK_ACTION_BUTTONS: { type: ActionType; label: string; confirm?: string }[] = [
  { type: 'quarantine', label: '隔離主機', confirm: '確定要隔離這台主機嗎?這會阻斷它的對外網路連線。' },
  { type: 'kill_process', label: '砍進程' },
]

// PA-410 syslog 掃描偵測(見 backend app/services/syslog_listener.py)觸發的
// 告警,host 欄位放的是攻擊來源 IP,不是主機名——封鎖按鈕只該對這幾種
// rule_name 出現,其他告警的 host 是主機名,對 PAN-OS 封鎖沒有意義。
// rule_name 常數必須跟後端 syslog_listener.py 的 RULE_NAME_* 完全一致。
const FIREWALL_RULE_NAMES = new Set([
  'PA-410 疑似連接埠掃描',
  'PA-410 疑似主機掃描',
  'PA-410 Threat Log 掃描/偵察特徵',
])

function highRiskActionButtonsFor(
  alert: Alert,
): { type: ActionType; label: string; confirm?: string }[] {
  if (!FIREWALL_RULE_NAMES.has(alert.rule_name ?? '')) return HIGH_RISK_ACTION_BUTTONS
  return [
    ...HIGH_RISK_ACTION_BUTTONS,
    {
      type: 'block_firewall_ip',
      label: '封鎖來源 IP',
      confirm: `確認要封鎖來源 IP ${alert.host ?? ''} 嗎?此動作會透過 PAN-OS User-ID API 立即生效。`,
    },
  ]
}

const SAFE_ACTION_BUTTONS: { type: ActionType; label: string; variant: 'primary' | 'success' }[] = [
  { type: 'mark_false_positive', label: '標記誤判', variant: 'primary' },
  { type: 'ignore', label: '忽略', variant: 'success' },
]

// 批次動作預設開放 SAFE_ACTION_BUTTONS 這兩個(標記誤判/忽略)——這兩個
// 不需要每筆告警各自的參數(不像 kill_process 要 pid、verify_file 要
// file_path),批次套用語意清楚。封鎖來源 IP 也加進批次(固定對外 IP
// 常態被掃描,一筆一筆封鎖太慢),但只有在選取的告警全部都是 PA-410
// syslog 觸發的(host 是真的 IP)才顯示這顆按鈕——隔離主機/砍進程這類
// 需要額外參數或風險模式不同的動作,還是維持只能單筆執行。

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
  const [fileClassification, setFileClassification] = useState<Record<string, FileClassification>>({})
  const [explainPending, setExplainPending] = useState<string | null>(null)
  const [explainError, setExplainError] = useState<Record<string, string>>({})
  const [relatedEvents, setRelatedEvents] = useState<Record<string, RelatedProcessEvent[]>>({})
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkPending, setBulkPending] = useState(false)
  const [bulkMessage, setBulkMessage] = useState<string | null>(null)

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
    // 篩選條件一變,原本選取的告警可能已經不在畫面上了,清空選取比留著
    // 「選到看不見的東西」更不容易讓人搞混。
    setSelectedIds(new Set())
  }, [loadAlerts])

  const sortedAlerts = useMemo(
    () => [...alerts].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [alerts],
  )

  const toggleSelected = (alertId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(alertId)) next.delete(alertId)
      else next.add(alertId)
      return next
    })
  }

  const allVisibleSelected = sortedAlerts.length > 0 && sortedAlerts.every((a) => selectedIds.has(a.alert_id))

  const toggleSelectAll = () => {
    setSelectedIds(allVisibleSelected ? new Set() : new Set(sortedAlerts.map((a) => a.alert_id)))
  }

  const selectedAlerts = sortedAlerts.filter((a) => selectedIds.has(a.alert_id))
  // 封鎖來源 IP 只有在選取的告警「全部」都是 PA-410 syslog 觸發的才給批次
  // 按鈕——混雜其他告警的話,host 不是 IP,送過去一定失敗,顯示這顆按鈕
  // 反而誤導。
  const canBulkBlock =
    selectedAlerts.length > 0 && selectedAlerts.every((a) => FIREWALL_RULE_NAMES.has(a.rule_name ?? ''))

  const performBulkAction = async (
    actionType: Extract<ActionType, 'ignore' | 'mark_false_positive' | 'block_firewall_ip'>,
    label: string,
  ) => {
    const ids = [...selectedIds]
    if (ids.length === 0) return
    if (!window.confirm(`確定要對選取的 ${ids.length} 筆告警套用「${label}」嗎?`)) return

    setBulkPending(true)
    setBulkMessage(null)
    try {
      const results = await Promise.allSettled(
        ids.map((id) => apiPost<ResponseAction>(`/api/alerts/${id}/actions`, { action_type: actionType })),
      )
      const failed = results.filter((r) => r.status === 'rejected').length
      const succeeded = results.length - failed
      setBulkMessage(
        failed === 0 ? `已對 ${succeeded} 筆告警套用「${label}」` : `成功 ${succeeded} 筆,失敗 ${failed} 筆`,
      )
      setSelectedIds(new Set())
      await loadAlerts()
    } finally {
      setBulkPending(false)
    }
  }

  const performAction = async (
    alert: Alert,
    actionType: ActionType,
    confirmMessage: string | undefined,
    prefill?: { pid?: number; filePath?: string },
  ) => {
    let pid: number | undefined = prefill?.pid
    let filePath: string | undefined = prefill?.filePath
    if (actionType === 'kill_process') {
      if (pid === undefined) {
        const input = window.prompt('要砍掉的進程 PID(告警本身沒有記錄觸發的 PID,需要人工確認後手動輸入):')
        if (!input) return
        pid = Number(input)
        if (!Number.isInteger(pid) || pid <= 0) {
          setActionMessage((prev) => ({ ...prev, [alert.alert_id]: 'PID 必須是正整數' }))
          return
        }
      }
      if (!window.confirm(`確定要在 ${alert.host ?? '這台主機'} 上砍掉 PID ${pid} 嗎?此動作無法復原。`)) {
        return
      }
    } else if (actionType === 'verify_file') {
      if (filePath === undefined) {
        const input = window.prompt('要驗證的檔案完整路徑(例如 C:\\Users\\Public\\suspicious.exe):')
        if (!input) return
        filePath = input
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
        file_path: filePath,
      })
      if (actionType === 'verify_file' && action.result) {
        try {
          const classification = JSON.parse(action.result) as FileClassification
          setFileClassification((prev) => ({ ...prev, [alert.alert_id]: classification }))
          setActionMessage((prev) => ({ ...prev, [alert.alert_id]: '' }))
        } catch {
          setActionMessage((prev) => ({ ...prev, [alert.alert_id]: action.result ?? '執行失敗' }))
        }
      } else {
        const message = action.result?.startsWith('failed:') ? action.result : '執行成功'
        setActionMessage((prev) => ({ ...prev, [alert.alert_id]: message }))
      }
      await loadAlerts()
    } catch (err) {
      const message = err instanceof ApiError ? err.message : '執行失敗'
      setActionMessage((prev) => ({ ...prev, [alert.alert_id]: message }))
    } finally {
      setActionPending(null)
    }
  }

  const toggleExpand = (alert: Alert) => {
    if (expanded === alert.alert_id) {
      setExpanded(null)
      return
    }
    setExpanded(alert.alert_id)
    if (!relatedEvents[alert.alert_id]) {
      apiGet<RelatedProcessEvent[]>(`/api/alerts/${alert.alert_id}/related-events`)
        .then((data) => setRelatedEvents((prev) => ({ ...prev, [alert.alert_id]: data })))
        .catch(() => setRelatedEvents((prev) => ({ ...prev, [alert.alert_id]: [] })))
    }
  }

  const explainAlert = async (alert: Alert, force: boolean) => {
    setExplainPending(alert.alert_id)
    setExplainError((prev) => ({ ...prev, [alert.alert_id]: '' }))
    try {
      const updated = await apiPost<Alert>(`/api/alerts/${alert.alert_id}/explain?force=${force}`)
      setAlerts((prev) => prev.map((a) => (a.alert_id === updated.alert_id ? updated : a)))
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'AI 說明產生失敗'
      setExplainError((prev) => ({ ...prev, [alert.alert_id]: message }))
    } finally {
      setExplainPending(null)
    }
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

      {user?.role === 'admin' && selectedIds.size > 0 && (
        <div className="toolbar" style={{ alignItems: 'center' }}>
          <span className="text-muted">已選取 {selectedIds.size} 筆</span>
          <div className="btn-row">
            {SAFE_ACTION_BUTTONS.map(({ type, label, variant }) => (
              <button
                key={type}
                className={`btn btn--sm btn--${variant}`}
                disabled={bulkPending}
                onClick={() => void performBulkAction(type as 'ignore' | 'mark_false_positive', label)}
              >
                批次{label}
              </button>
            ))}
            {canBulkBlock && (
              <button
                className="btn btn--sm btn--danger"
                disabled={bulkPending}
                onClick={() => void performBulkAction('block_firewall_ip', '封鎖來源 IP')}
              >
                批次封鎖來源 IP
              </button>
            )}
          </div>
          {bulkMessage && <span className="text-muted">{bulkMessage}</span>}
        </div>
      )}

      {!loading && sortedAlerts.length === 0 ? (
        <p className="text-muted">目前沒有符合條件的告警。</p>
      ) : (
        <div className={`table-wrap${loading ? ' table-wrap--loading' : ''}`}>
          {loading && <LoadingOverlay />}
          <table className="data-table">
            <thead>
              <tr>
                {user?.role === 'admin' && (
                  <th>
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={toggleSelectAll}
                      aria-label="全選"
                    />
                  </th>
                )}
                <th>Severity</th>
                <th>主機</th>
                <th>規則名稱</th>
                <th>觸發時間</th>
                <th>狀態</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {!loading &&
                sortedAlerts.map((alert) => (
                <Fragment key={alert.alert_id}>
                  <tr className="row">
                    {user?.role === 'admin' && (
                      <td>
                        <input
                          type="checkbox"
                          checked={selectedIds.has(alert.alert_id)}
                          onChange={() => toggleSelected(alert.alert_id)}
                          aria-label={`選取 ${alert.rule_name ?? alert.alert_id}`}
                        />
                      </td>
                    )}
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
                      <button className="btn btn--ghost btn--sm" onClick={() => toggleExpand(alert)}>
                        {expanded === alert.alert_id ? '收合' : '詳情'}
                      </button>
                    </td>
                  </tr>
                  {expanded === alert.alert_id && (
                    <tr className="detail-row">
                      <td colSpan={user?.role === 'admin' ? 7 : 6}>
                        <div className="detail-panel">
                          <p style={{ marginBottom: 8 }}>
                            <strong>AI 說明:</strong> {alert.ai_explanation ?? '尚未產生'}
                          </p>
                          <div className="btn-row" style={{ alignItems: 'center', marginBottom: 12 }}>
                            <button
                              className="btn btn--sm"
                              disabled={explainPending === alert.alert_id}
                              onClick={() => void explainAlert(alert, Boolean(alert.ai_explanation))}
                            >
                              {alert.ai_explanation ? '重新產生 AI 說明' : '產生 AI 說明'}
                            </button>
                            {explainError[alert.alert_id] && (
                              <span className="alert-message">{explainError[alert.alert_id]}</span>
                            )}
                          </div>
                          <div style={{ marginBottom: 12 }}>
                            <p className="text-muted" style={{ marginBottom: 8 }}>
                              <strong>相關進程活動</strong>(同主機、前後 10 分鐘內):
                            </p>
                            {!relatedEvents[alert.alert_id] ? (
                              <div className="state-message" style={{ padding: 0 }}>
                                <span className="spinner" />
                                載入中…
                              </div>
                            ) : relatedEvents[alert.alert_id].length === 0 ? (
                              <p className="text-faint">沒有找到相關的進程事件。</p>
                            ) : (
                              <table className="data-table">
                                <thead>
                                  <tr>
                                    <th>時間</th>
                                    <th>PID</th>
                                    <th>使用者</th>
                                    <th>路徑</th>
                                    <th>指令</th>
                                    {user?.role === 'admin' && <th />}
                                  </tr>
                                </thead>
                                <tbody>
                                  {relatedEvents[alert.alert_id].map((event, i) => (
                                    // eslint-disable-next-line react/no-array-index-key -- process_events 沒有回傳唯一 id
                                    <tr key={i}>
                                      <td className="text-muted">
                                        {event.timestamp ? new Date(event.timestamp).toLocaleString() : '-'}
                                      </td>
                                      <td>{event.pid ?? '-'}</td>
                                      <td className="text-muted">{event.user ?? '-'}</td>
                                      <td>{event.image ?? '-'}</td>
                                      <td className="text-faint">{event.command_line ?? '-'}</td>
                                      {user?.role === 'admin' && (
                                        <td>
                                          <div className="btn-row">
                                            {event.image && (
                                              <button
                                                className="btn btn--outline btn--sm"
                                                disabled={actionPending === alert.alert_id}
                                                onClick={() =>
                                                  void performAction(alert, 'verify_file', undefined, {
                                                    filePath: event.image ?? undefined,
                                                  })
                                                }
                                              >
                                                驗證此檔案
                                              </button>
                                            )}
                                            {event.pid != null && (
                                              <button
                                                className="btn btn--danger btn--sm"
                                                disabled={actionPending === alert.alert_id}
                                                onClick={() =>
                                                  void performAction(alert, 'kill_process', undefined, {
                                                    pid: event.pid ?? undefined,
                                                  })
                                                }
                                              >
                                                砍此進程
                                              </button>
                                            )}
                                          </div>
                                        </td>
                                      )}
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </div>
                          {user?.role === 'admin' && (
                            <div>
                              <div className="btn-row" style={{ marginBottom: 12 }}>
                                <button
                                  className="btn btn--sm btn--outline"
                                  disabled={actionPending === alert.alert_id}
                                  onClick={() => void performAction(alert, 'verify_file', undefined)}
                                >
                                  驗證檔案類型
                                </button>
                              </div>
                              {fileClassification[alert.alert_id] && (
                                <div className="detail-panel" style={{ marginBottom: 12 }}>
                                  {(() => {
                                    const c = fileClassification[alert.alert_id]
                                    return (
                                      <p className="text-muted">
                                        <strong>{c.declared_path}</strong> — 偵測類型:{c.detected_label}(
                                        {c.detected_mime_type})
                                        {c.extension_mismatch ? (
                                          <span className="pill pill--danger" style={{ marginLeft: 8 }}>
                                            副檔名不符,疑似偽裝
                                          </span>
                                        ) : (
                                          <span className="pill pill--success" style={{ marginLeft: 8 }}>
                                            類型相符
                                          </span>
                                        )}
                                      </p>
                                    )
                                  })()}
                                </div>
                              )}
                              <div className="btn-row" style={{ gap: 24 }}>
                                <div className="btn-row">
                                  {highRiskActionButtonsFor(alert).map(({ type, label, confirm }) => (
                                    <button
                                      key={type}
                                      className="btn btn--sm btn--danger"
                                      disabled={actionPending === alert.alert_id}
                                      onClick={() => void performAction(alert, type, confirm)}
                                    >
                                      {label}
                                    </button>
                                  ))}
                                </div>
                                <div className="btn-row">
                                  {SAFE_ACTION_BUTTONS.map(({ type, label, variant }) => (
                                    <button
                                      key={type}
                                      className={`btn btn--sm btn--${variant}`}
                                      disabled={actionPending === alert.alert_id}
                                      onClick={() => void performAction(alert, type, undefined)}
                                    >
                                      {label}
                                    </button>
                                  ))}
                                </div>
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
