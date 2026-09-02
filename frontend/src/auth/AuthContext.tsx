import { createContext, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { apiGet, ApiError } from '../lib/api'

export type Role = 'admin' | 'viewer'

export interface CurrentUser {
  email: string
  role: Role
}

interface AuthState {
  user: CurrentUser | null
  loading: boolean
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const me = await apiGet<CurrentUser>('/auth/me')
      setUser(me)
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setUser(null)
      } else {
        throw error
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
    // 只在掛載時查一次登入狀態,refresh 之後由呼叫端自己決定要不要再叫。
    // eslint-disable-next-line react-hooks/exhaustive-deps -- 見上面註解
  }, [])

  return <AuthContext.Provider value={{ user, loading, refresh }}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return ctx
}
