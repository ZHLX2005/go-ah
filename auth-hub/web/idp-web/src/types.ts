/**
 * IDP 前端类型定义
 * 显式定义 OAuth2/OIDC 参数与用户信息，保证类型安全
 */

/** 用户信息 */
export interface UserInfo {
  id: number
  username: string
  nickname: string
  email: string
}

/** 授权确认页所需的展示数据（来自 GET /api/consent） */
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

/** OIDC 授权请求参数（/oauth2/auth 透传到前端页面） */
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

/** 统一 API 响应；__status 为 HTTP 状态码，便于前端区分 401/403 */
export interface ApiResponse<T> {
  code: number
  data?: T
  error?: string
  message?: string
  /** HTTP 状态码（由前端请求层注入） */
  __status?: number
}

/** 从 URLSearchParams 解析授权参数 */
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
