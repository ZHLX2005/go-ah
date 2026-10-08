/**
 * 端点封装：一一对应 auth-hub 的路由。
 * 页面只用这里的函数，不直接拼路径 —— 后端改路径时只改这一个文件。
 *
 * 三类路径在部署时要被 nginx 反代到 auth-hub 容器：
 *   /api          页面配套 API（登录、授权确认、管理后台）
 *   /oauth2       OIDC 端点
 *   /.well-known  发现文档与 JWKS
 */
import { http, request } from './client'
import type {
  AdminUser,
  AuthParams,
  ClientInput,
  ClientRow,
  ConsentInfo,
  CreatedClient,
  LoginResult,
  RefreshTokenRow,
  SessionRow,
  UserInfo,
  UserRow,
} from './types'

// ══ 认证流 ══════════════════════════════════════════════════════════════════

export const authApi = {
  /**
   * 账号密码登录。失败时后端返回 {code:1, error:'user_not_found'|'wrong_password'}，
   * 客户端会把 error 放进 ApiFailure.reason —— 登录页据此给出「账号不存在 / 密码错误」
   * 这类可区分的提示（分不清的话用户不知道该改哪个）。
   */
  login: (username: string, password: string, returnTo: string) =>
    http.post<LoginResult>('/api/login', {
      username,
      password,
      return_to: returnTo,
    }),

  /** 当前登录态；未登录时 data 为 null 而不是报错 */
  me: () => http.get<UserInfo | null>('/api/me'),

  /** 登出：销毁全局会话 + 吊销该用户全部 refresh_token */
  logout: (postLogoutRedirectURI: string, state: string) =>
    request<Record<string, unknown>>('POST', '/api/logout', {
      body: { post_logout_redirect_uri: postLogoutRedirectURI, state },
    }),

  /** 授权确认页的展示数据（裸对象，非信封） */
  consentInfo: (params: URLSearchParams) =>
    request<ConsentInfo>('GET', '/api/consent', {
      query: Object.fromEntries(params.entries()),
    }),

  /**
   * 提交授权决定。同意 → 返回 {redirect_to}（带 code 回调业务方）；
   * 拒绝 → 也返回 {redirect_to}，但地址上带 error=access_denied。
   * 响应是裸对象，不是信封。
   */
  submitConsent: (payload: AuthParams & { decision: 'allow' | 'deny' }) =>
    request<{ redirect_to?: string; error?: string }>('POST', '/api/consent', { body: payload }),
}

// ══ 管理后台（需全局会话 + users.is_admin）══════════════════════════════════

export const adminApi = {
  /** 身份探测：401 未登录 / 403 非管理员（客户端按 HTTP 状态抛出） */
  me: () => http.get<AdminUser>('/api/admin/me'),

  users: () => http.get<UserRow[]>('/api/admin/users'),
  userSessions: (id: number) => http.get<SessionRow[]>(`/api/admin/users/${id}/sessions`),
  userTokens: (id: number) => http.get<RefreshTokenRow[]>(`/api/admin/users/${id}/tokens`),

  clients: () => http.get<ClientRow[]>('/api/admin/clients'),

  /** 创建客户端：返回整个信封，因为 client_secret 在 data 的同级 */
  createClient: (payload: ClientInput) =>
    request<CreatedClient & { code: number; data: ClientRow }>('POST', '/api/admin/clients', {
      body: payload,
      returnEnvelope: true,
    }),

  updateClient: (id: number, payload: Partial<ClientInput>) =>
    http.put<ClientRow>(`/api/admin/clients/${id}`, payload),

  deleteClient: (id: number) => http.del<null>(`/api/admin/clients/${id}`),

  /** refresh_token 列表；status: all | active | revoked */
  refreshTokens: (status: string) =>
    http.get<RefreshTokenRow[]>('/api/admin/refresh-tokens', { status }),

  revokeToken: (id: number) => http.post<null>('/api/admin/revoke-token', { id }),
}
