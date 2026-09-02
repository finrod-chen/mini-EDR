import type { Severity } from './types'

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low']

export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: '#7f1d1d',
  High: '#b91c1c',
  Medium: '#b45309',
  Low: '#6b7280',
}

export function severityRank(severity: string | null): number {
  if (severity && severity in SEVERITY_RANK) {
    return SEVERITY_RANK[severity as Severity]
  }
  return SEVERITY_ORDER.length
}
