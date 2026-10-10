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
  InviteInput,
  InviteRow,
  InviteUpdateInput,
  InviteUsageRow,
  LoginResult,
  QRClaimResult,
  QRPollResult,
  QRPreviewResult,
  QRSessionCreated,
  QRStatusResult,
  RefreshTokenRow,
  RegisterInput,
  RegisterResult,
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

  /**
   * 凭邀请码自助注册。成功即登录（后端下发会话 Cookie），返回与登录同形的
   * {username, nickname, return_to}。
   *
   * 失败时 error 字段是**可分支的原因码**，注册页据此给出针对性提示：
   *   invite_not_found / invite_disabled / invite_expired / invite_exhausted
   *   username_taken / invalid_username / invalid_password / invalid_email
   * 只说一句「注册失败」的话，用户唯一能做的就是整页重填一遍。
   */
  register: (payload: RegisterInput) => http.post<RegisterResult>('/api/register', payload),

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

// ══ 扫码登录 ════════════════════════════════════════════════════════════════

/**
 * 扫码登录端点。设计文档见 docs/design/qr-login.md，此处只列调用口径。
 *
 * 分成 pc / mobile 两组不是为了好看，而是因为两边的**凭据完全不同**：
 *   pc 组依赖后端下发的 qr_ctx Cookie（fetch 的 credentials:'include' 自动带上），
 *        调用方本身不需要登录；
 *   mobile 组依赖 idp_session Cookie（H5 路径）或 Bearer token（App 路径），
 *        未登录时一律 401，页面必须按 reason==='unauthenticated' 去跳登录。
 * 混用会出事故：让 PC 去调 mobile 组的接口，未登录时会拿到 401 而不是 pending。
 */
export const qrApi = {
  // ── PC 侧 ────────────────────────────────────────────────────────────────

  /**
   * 创建一张待扫码票据。
   *
   * **不接受任何入参**：要在手机上展示的设备画像由服务端从请求头解析。
   * 允许前端传"我是 Windows Chrome"，就等于允许攻击者伪造用户唯一能核对的那条信息。
   * 同时 return_to 也不发给后端 —— 票据只代表"有台机器想登录"，
   * 不代表"登录完要去授权哪个应用"，否则受害者的批准会被用来完成攻击者的授权。
   */
  create: () => http.post<QRSessionCreated>('/api/qr/sessions', {}),

  /** 轮询状态（只读、无副作用；领取是独立的 claim） */
  poll: (ticket: string) => http.get<QRPollResult>(`/api/qr/sessions/${encodeURIComponent(ticket)}`),

  /**
   * 领取登录态。**唯一**会下发 idp_session 的扫码端点。
   *
   * 失败（qr_not_ready / qr_expired / 已消费…）由 ApiFailure 抛出，
   * 调用方必须把它当成"还要继续等或该刷新二维码"，而不是当成登录成功。
   */
  claim: (ticket: string) =>
    http.post<QRClaimResult>(`/api/qr/sessions/${encodeURIComponent(ticket)}/claim`, {}),

  /** 作废当前票据（换一张新二维码之前调，避免旧码还能被领） */
  cancel: (ticket: string) =>
    http.post<{ message: string }>(`/api/qr/sessions/${encodeURIComponent(ticket)}/cancel`, {}),

  // ── 手机侧（需已有身份）────────────────────────────────────────────────────

  /** 确认页取数：把"要被登录的那台机器"的画像拿给手机上的人看 */
  preview: (ticket: string) =>
    http.get<QRPreviewResult>(`/api/qr/sessions/${encodeURIComponent(ticket)}/preview`),

  /** 标记已扫码，驱动 PC 端显示"已扫码，等待确认" */
  scan: (ticket: string) =>
    http.post<QRStatusResult>(`/api/qr/sessions/${encodeURIComponent(ticket)}/scan`, {}),

  /** 批准这次登录 —— 整个扫码流程里唯一的授权动作 */
  confirm: (ticket: string) =>
    http.post<QRStatusResult>(`/api/qr/sessions/${encodeURIComponent(ticket)}/confirm`, {}),

  /** "不是我操作的要登录"：拒绝并作废票据 */
  refuse: (ticket: string) =>
    http.post<{ message: string }>(`/api/qr/sessions/${encodeURIComponent(ticket)}/refuse`, {}),
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

  // ── 注册邀请码 ────────────────────────────────────────────────────────────

  /** 邀请码列表；status 传 'all' 或省略为全部（过滤在后端做，见 ListByStatus） */
  invites: (status: string) => http.get<InviteRow[]>('/api/admin/invites', { status }),

  createInvite: (payload: InviteInput) => http.post<InviteRow>('/api/admin/invites', payload),

  /** 未给出的字段不改；expires_at 传空串 = 改为长期有效 */
  updateInvite: (id: number, payload: InviteUpdateInput) =>
    http.put<InviteRow>(`/api/admin/invites/${id}`, payload),

  deleteInvite: (id: number) => http.del<null>(`/api/admin/invites/${id}`),

  /** 使用明细：谁在哪一刻用这张码注册了哪个账号 */
  inviteUsages: (id: number) => http.get<InviteUsageRow[]>(`/api/admin/invites/${id}/usages`),
}
