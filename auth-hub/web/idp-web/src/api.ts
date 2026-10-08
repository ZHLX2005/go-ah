import type { ApiResponse, UserInfo } from './types'

/** 通用 fetch 封装：统一处理 JSON 与错误 */
async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: 'include', // 携带 IDP 全局会话 Cookie
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  const data = (await res.json()) as T
  return data
}

/** 登录：POST /api/login */
export async function login(
  username: string,
  password: string,
  returnTo: string,
): Promise<ApiResponse<{ username: string; nickname: string; return_to: string }>> {
  return request('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, return_to: returnTo }),
  })
}

/** 当前登录态：GET /api/me */
export async function me(): Promise<ApiResponse<UserInfo | null>> {
  return request('/api/me')
}

/** 拉取授权确认页展示信息：GET /api/consent?... */
export async function getConsentInfo(search: string): Promise<ApiResponse<never> & Record<string, unknown>> {
  return request(`/api/consent${search}`)
}

/** 提交授权决定：POST /api/consent */
export async function submitConsent(payload: {
  client_id: string
  redirect_uri: string
  scope: string
  state: string
  nonce: string
  code_challenge: string
  code_challenge_method: string
  decision: 'allow' | 'deny'
}): Promise<{ redirect_to: string } | { error: string }> {
  return request('/api/consent', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
