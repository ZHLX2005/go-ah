/**
 * 后端契约类型（对照 auth-hub/api/*.go 手写，字段名与线上 JSON 一致）。
 *
 * 一律保留 **snake_case**：后端就是这么发的，中间加一层驼峰映射只会多一处
 * 对不上的地方。上一版是分散在各页面里的局部 interface，这里收到一处。
 *
 * 时间字段都是 Go 的 time.Time，序列化为 RFC3339（形如 2026-10-08T14:00:00Z），
 * 展示时一律过 lib/format.ts 的 fmtTime。
 */

// ══ 身份 ════════════════════════════════════════════════════════════════════

/** GET /api/me 的登录用户 */
export interface UserInfo {
  id: number
  username: string
  nickname: string
  email: string
}

/** GET /api/admin/me 的管理员（比 UserInfo 多 is_admin） */
export interface AdminUser extends UserInfo {
  is_admin: boolean
}

// ══ 认证流 ══════════════════════════════════════════════════════════════════

/** POST /api/login 成功后的 data */
export interface LoginResult {
  username: string
  nickname: string
  /** 后端拼好的回跳地址：回到 /oauth2/auth 继续授权流程 */
  return_to: string
}

/**
 * GET /api/consent 的响应 —— **裸对象，不是信封**。
 * 展示授权确认页所需的一切：申请方、当前账号、申请的 scope。
 */
export interface ConsentInfo {
  client_name: string
  client_id: string
  scopes: string[]
  user: {
    username: string
    nickname: string
    email: string
  }
}

/** OIDC 授权请求参数（/oauth2/auth 透传到 /consent 页面） */
export interface AuthParams {
  client_id: string
  redirect_uri: string
  response_type: string
  scope: string
  state: string
  nonce: string
  code_challenge: string
  code_challenge_method: string
}

/** 从 URLSearchParams 解析授权参数，缺项给 OIDC 惯例默认值 */
export function parseAuthParams(sp: URLSearchParams): AuthParams {
  return {
    client_id: sp.get('client_id') ?? '',
    redirect_uri: sp.get('redirect_uri') ?? '',
    response_type: sp.get('response_type') ?? 'code',
    scope: sp.get('scope') ?? 'openid',
    state: sp.get('state') ?? '',
    nonce: sp.get('nonce') ?? '',
    code_challenge: sp.get('code_challenge') ?? '',
    code_challenge_method: sp.get('code_challenge_method') ?? 'S256',
  }
}

// ══ 管理台 ══════════════════════════════════════════════════════════════════

/** GET /api/admin/users 的行 */
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

/** GET /api/admin/users/:id/sessions 的行（session_id 已脱敏） */
export interface SessionRow {
  session_id: string
  expires_at: string
  created_at: string
}

/** OIDC 客户端；client_secret 不回传，只有 has_secret 标记 */
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

/** refresh_token 行（token 已脱敏） */
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

/** 创建客户端时的请求体（后端接受数组形式的 uris / scopes） */
export interface ClientInput {
  client_id: string
  client_name?: string
  redirect_uris: string[]
  scopes?: string[]
  is_public?: boolean
  pkce_required?: boolean
  enabled?: boolean
  post_logout_uris?: string[]
  /** 留空则后端自动生成 cs_ 前缀密钥（仅机密客户端需要） */
  client_secret?: string
}

/** 创建客户端的响应：机密客户端会额外带回一次性明文 secret */
export interface CreatedClient {
  client: ClientRow
  client_secret?: string
  notice?: string
}

export const TOKEN_STATUS_OPTIONS = [
  { value: 'all', label: '全部' },
  { value: 'active', label: '有效' },
  { value: 'revoked', label: '已吊销' },
]

export const SCOPE_OPTIONS = ['openid', 'profile', 'email']
