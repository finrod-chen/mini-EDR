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
    throw new ApiError(response.status, `${init?.method ?? 'GET'} ${path} failed (${response.status})`)
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

export function apiPost<T>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: 'POST' })
}

export function loginUrl(): string {
  return `${API_BASE_URL}/auth/login`
}
