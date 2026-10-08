/**
 * 模板业务平台 - 类型定义
 * 为 OIDC 参数与用户信息提供类型安全约束
 */

/** 业务后端下发的 OIDC 公共配置（不含 client_secret） */
export interface OidcPublicConfig {
  client_id: string
  redirect_uri: string
  scope: string
  post_logout_uri: string
  idp_issuer: string
  authorization_endpoint: string
  token_endpoint?: string
  end_session_endpoint: string
  idp_available: boolean
  idp_error?: string
}

/** 业务用户信息（来自 GET /api/profile） */
export interface Profile {
  sub: string
  username: string
  nickname: string
  email: string
  last_login_at: string
  session_expires_at: string
  has_id_token: boolean
  has_refresh_token: boolean
}

/**
 * PKCE 授权参数集合
 * 浏览器侧生成，存放于 sessionStorage 供回调页校验使用
 */
export interface PkceState {
  state: string
  code_verifier: string
  code_challenge: string
  redirect_uri: string
  created_at: number
}

/** PKCE 参数在 sessionStorage 中的键名 */
export const PKCE_STORAGE_KEY = 'oidc_pkce_state'
