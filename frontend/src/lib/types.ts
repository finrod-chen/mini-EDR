export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type AlertStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive'

export interface Alert {
  alert_id: string
  severity: Severity | null
  rule_name: string | null
  host: string | null
  status: AlertStatus | null
  ai_explanation: string | null
  created_at: string | null
}

export interface ResponseAction {
  action_id: string
  alert_id: string | null
  host: string | null
  action_type: string | null
  performed_by: string | null
  performed_at: string | null
  result: string | null
}

export interface Asset {
  asset_id: string
  hostname: string | null
  ip: string | null
  os_version: string | null
  vendor: string | null
  model: string | null
  cpu: string | null
  memory: string | null
  defender_status: string | null
  defender_last_scan: string | null
  defender_signature_date: string | null
  last_seen: string | null
  health_score: number
}

export interface Software {
  software_name: string | null
  version: string | null
  publisher: string | null
  install_date: string | null
}
