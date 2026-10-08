/**
 * ============================================================
 * OIDC PKCE 工具库（业务接入参考脚手架核心文件）
 * ============================================================
 *
 * 使用 openid-client (v5) 生成 PKCE 参数，遵循 OAuth 2.0 / OIDC 1.0 规范：
 *   1. 生成 state（防 CSRF）
 *   2. 生成 code_verifier（随机字符串，128 位熵以上）
 *   3. 生成 code_challenge = BASE64URL(SHA256(code_verifier))  即 S256
 *   4. 组装授权 URL 并跳转
 *   5. 回调时从 sessionStorage 取回 verifier，随 code 一起提交给业务后端
 *
 * 安全要点：
 *   - SPA 属公共客户端，**不能**保存 client_secret，必须使用 PKCE
 *   - id_token 的签名校验全部在业务 Go 后端完成，前端不做任何 JWT 验签
 *   - token 不落 localStorage，由后端保管（方案1）
 */
import { generators, Issuer } from 'openid-client'
import type { OidcPublicConfig, PkceState } from './types'
import { PKCE_STORAGE_KEY } from './types'

/** 拉取业务后端下发的 OIDC 公共配置 */
export async function fetchOidcConfig(): Promise<OidcPublicConfig> {
  const res = await fetch('/api/config', { credentials: 'include' })
  if (!res.ok) throw new Error('获取 OIDC 配置失败')
  return (await res.json()) as OidcPublicConfig
}

/**
 * 生成 PKCE 参数并写入 sessionStorage
 * @returns 可直接跳转的授权 URL
 */
export async function buildAuthorizationUrl(cfg: OidcPublicConfig): Promise<string> {
  // 1) 构建 Issuer（本地 http 环境需允许非 HTTPS）
  const issuer = new Issuer({
    issuer: cfg.idp_issuer,
    authorization_endpoint: cfg.authorization_endpoint,
    token_endpoint: cfg.token_endpoint ?? cfg.idp_issuer + '/oauth2/token',
    end_session_endpoint: cfg.end_session_endpoint,
  })
  const client = new issuer.Client({
    client_id: cfg.client_id,
    redirect_uris: [cfg.redirect_uri],
    response_types: ['code'],
    // 公共客户端：token_endpoint_auth_method = none，无 client_secret
    token_endpoint_auth_method: 'none',
  })

  // 2) 生成 state / code_verifier / code_challenge(S256)
  const state = generators.state()
  const codeVerifier = generators.codeVerifier()
  const codeChallenge = generators.codeChallenge(codeVerifier)

  // 3) 持久化到 sessionStorage，回调页需用 verifier 换 token
  const stored: PkceState = {
    state,
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    redirect_uri: cfg.redirect_uri,
    created_at: Date.now(),
  }
  sessionStorage.setItem(PKCE_STORAGE_KEY, JSON.stringify(stored))

  // 4) 生成带全部 PKCE 参数的授权 URL
  return client.authorizationUrl({
    scope: cfg.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    nonce: generators.nonce(),
  })
}

/** 读取并清除 PKCE 临时状态 */
export function takeStoredPkce(): PkceState | null {
  const raw = sessionStorage.getItem(PKCE_STORAGE_KEY)
  if (!raw) return null
  sessionStorage.removeItem(PKCE_STORAGE_KEY)
  try {
    return JSON.parse(raw) as PkceState
  } catch {
    return null
  }
}

/**
 * 发起 PKCE 授权跳转
 * 由首页在"未登录"状态下自动调用
 */
export async function startLogin(): Promise<void> {
  const cfg = await fetchOidcConfig()
  const url = await buildAuthorizationUrl(cfg)
  window.location.href = url
}
