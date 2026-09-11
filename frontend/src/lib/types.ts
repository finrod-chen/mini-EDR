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

export type ActionType = 'quarantine' | 'kill_process' | 'ignore' | 'mark_false_positive' | 'verify_file'

export interface FileClassification {
  declared_path: string
  file_size: number
  sha256: string
  detected_label: string
  detected_mime_type: string
  detected_extensions: string[]
  extension_mismatch: boolean
}

export interface RelatedProcessEvent {
  timestamp: string | null
  pid: number | null
  ppid: number | null
  user: string | null
  image: string | null
  command_line: string | null
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

export interface HealthScoreDeduction {
  reason: string
  points: number
}

export type MonitorType = 'velociraptor' | 'snmp'
export type DeviceType = 'printer' | 'nas' | 'firewall' | 'other'

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
  monitor_type: MonitorType | null
  device_type: DeviceType | null
  snmp_sys_descr: string | null
  snmp_uptime_seconds: number | null
  snmp_last_poll_ok: boolean | null
  health_score: number
  health_score_breakdown: HealthScoreDeduction[]
}

export interface Software {
  software_name: string | null
  version: string | null
  publisher: string | null
  install_date: string | null
}
