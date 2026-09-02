const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? 'http://localhost:8000'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...init?.headers,
    },
  })

  if (!response.ok) {
    // FastAPI 的 HTTPException 回應是 {"detail": "..."},盡量把 detail 顯示
    // 出來,拿不到就退回泛用訊息。
    let detail = `${init?.method ?? 'GET'} ${path} failed (${response.status})`
    try {
      const body = (await response.json()) as { detail?: string }
      if (body.detail) detail = body.detail
    } catch {
      // 回應不是 JSON,用上面的泛用訊息就好。
    }
    throw new ApiError(response.status, detail)
  }

  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

export function apiGet<T>(path: string, params?: Record<string, string | undefined>): Promise<T> {
  const query = params
    ? '?' +
      new URLSearchParams(
        Object.entries(params).filter((entry): entry is [string, string] => entry[1] !== undefined),
      ).toString()
    : ''
  return apiFetch<T>(`${path}${query}`)
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export function loginUrl(): string {
  return `${API_BASE_URL}/auth/login`
}
