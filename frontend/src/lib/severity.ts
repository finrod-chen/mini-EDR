import type { Severity } from './types'

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low']

export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
}

export function severityRank(severity: string | null): number {
  if (severity && severity in SEVERITY_RANK) {
    return SEVERITY_RANK[severity as Severity]
  }
  return SEVERITY_ORDER.length
}
