import type { ApiResponse } from './types'

/**
 * 管理后台 API 客户端
 * 全部接口依赖 IDP 全局会话 Cookie，后端会校验 users.is_admin
 */

/** 通用请求封装 */
async function request<T>(url: string, init?: RequestInit): Promise<T & { __status: number }> {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    data = {}
  }
  return { ...(data as object), __status: res.status } as T & { __status: number }
}

// ============ 类型定义 ============

/** 管理员信息 */
export interface AdminUser {
  id: number
  username: string
  nickname: string
  email: string
  is_admin: boolean
}

/** 用户列表行 */
export interface UserRow {
  id: number
  username: string
  email: string
  nickname: string
  is_admin: boolean
  created_at: string
  session_count: number
  refresh_token_count: number
  active_refresh_count: number
}

/** 会话行 */
export interface SessionRow {
  session_id: string
  expires_at: string
  created_at: string
}

/** OIDC 客户端 */
export interface ClientRow {
  id: number
  client_id: string
  client_name: string
  redirect_uris: string[]
  scopes: string[]
  is_public: boolean
  pkce_required: boolean
  enabled: boolean
  post_logout_uris: string[]
  created_at: string
  has_secret: boolean
}

/** refresh_token 行 */
export interface RefreshTokenRow {
  id: number
  token: string
  user_id: number
  user_sub: string
  username: string
  client_id: string
  scope: string
  expires_at: string
  revoked: boolean
  revoked_at: string | null
  created_at: string
  expired: boolean
}

// ============ 接口 ============

/** 当前管理员身份；401 未登录，403 非管理员 */
export async function fetchAdminMe(): Promise<ApiResponse<AdminUser>> {
  return request<ApiResponse<AdminUser>>('/api/admin/me')
}

/** 用户列表 */
export async function fetchUsers(): Promise<ApiResponse<UserRow[]>> {
  return request('/api/admin/users')
}

/** 指定用户的活跃会话 */
export async function fetchUserSessions(id: number): Promise<ApiResponse<SessionRow[]>> {
  return request(`/api/admin/users/${id}/sessions`)
}

/** 指定用户的 refresh_token */
export async function fetchUserTokens(id: number): Promise<ApiResponse<RefreshTokenRow[]>> {
  return request(`/api/admin/users/${id}/tokens`)
}

/** 客户端列表 */
export async function fetchClients(): Promise<ApiResponse<ClientRow[]>> {
  return request('/api/admin/clients')
}

/** 创建客户端（非公共客户端会返回一次明文 client_secret） */
export async function createClient(payload: Partial<ClientRow>): Promise<
  ApiResponse<ClientRow> & { client_secret?: string; notice?: string }
> {
  return request('/api/admin/clients', { method: 'POST', body: JSON.stringify(payload) })
}

/** 更新客户端 */
export async function updateClient(id: number, payload: Partial<ClientRow>): Promise<ApiResponse<ClientRow>> {
  return request(`/api/admin/clients/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
}

/** 删除客户端 */
export async function deleteClient(id: number): Promise<ApiResponse<never>> {
  return request(`/api/admin/clients/${id}`, { method: 'DELETE' })
}

/** refresh_token 列表；status: all | active | revoked */
export async function fetchRefreshTokens(status: string = 'all'): Promise<ApiResponse<RefreshTokenRow[]>> {
  return request(`/api/admin/refresh-tokens?status=${encodeURIComponent(status)}`)
}

/** 吊销指定 refresh_token（按 id） */
export async function revokeToken(id: number): Promise<ApiResponse<never>> {
  return request('/api/admin/revoke-token', { method: 'POST', body: JSON.stringify({ id }) })
}
