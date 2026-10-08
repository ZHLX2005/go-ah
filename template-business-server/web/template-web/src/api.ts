import type { Profile } from './types'

/** 通用 fetch：携带业务会话 Cookie */
async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  const data = await res.json()
  return { ...data, __status: res.status } as T
}

/** 受保护接口：获取当前用户信息 */
export async function fetchProfile(): Promise<{ code: number; data?: Profile; error?: string; __status: number }> {
  return request('/api/profile')
}

/**
 * 回调处理：把 code + state + code_verifier 提交给业务后端
 * 由后端完成 token 交换与 id_token 校验（方案1）
 */
export async function exchangeCode(payload: {
  code: string
  state: string
  code_verifier: string
  redirect_uri: string
}): Promise<{ code?: number; data?: unknown; error?: string; message?: string; __status: number }> {
  return request('/api/auth/callback', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

/** 轻量登录态探测 */
export async function fetchSession(): Promise<{ code: number; data: { sub: string; expires_at: string } | null }> {
  return request('/api/session')
}

/** 业务登出：销毁业务会话，返回 IDP 统一登出地址 */
export async function logout(): Promise<{ code: number; logout_url: string }> {
  return request('/api/logout', { method: 'POST' })
}

/** 刷新 token（测试用例 6） */
export async function refreshToken(): Promise<{ code?: number; message?: string; error?: string }> {
  return request('/api/refresh', { method: 'POST' })
}
