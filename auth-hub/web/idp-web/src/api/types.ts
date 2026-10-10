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

/** 注册表单的三项输入 + 邀请码（全平台唯一的自助注册入口） */
export interface RegisterInput {
  username: string
  password: string
  email: string
  invite_code: string
  return_to: string
}

/**
 * POST /api/register 成功后的 data —— 与 LoginResult **同形**。
 * 注册成功即登录，之后走与登录完全相同的链路（回到原授权请求），
 * 所以前端可以复用同一段处理逻辑。
 */
export type RegisterResult = LoginResult

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

// ══ 扫码登录 ════════════════════════════════════════════════════════════════

/**
 * 扫码票据状态。取值与后端 entity.QRStatus* 一一对应，**是契约不是提示**：
 * QrPanel 按它分支渲染，少认一个值就会把界面卡在默认分支上。
 *
 * expired 是服务端算出来的（库里并不存这个值）—— 过期与否由 expires_at
 * 决定，如果只靠后端定时改写状态，服务重启期间的票据会一直显示 pending。
 */
export type QRStatus =
  | 'pending'
  | 'scanned'
  | 'confirmed'
  | 'consumed'
  | 'cancelled'
  | 'expired'

/** POST /api/qr/sessions 的 data */
export interface QRSessionCreated {
  ticket: string
  /** 二维码的内容：一个 https URL，手机扫出来直接打开它 */
  qr_content: string
  /** 票据存活秒数（服务端时钟为准，前端拿它画倒计时） */
  expires_in: number
  /** 建议轮询间隔（毫秒），由服务端下发 */
  interval_ms: number
}

/** GET /api/qr/sessions/{ticket} 的 data */
export interface QRPollResult {
  status: QRStatus
  expires_in: number
}

/** POST /api/qr/sessions/{ticket}/claim 的 data（与 LoginResult 去掉 return_to） */
export interface QRClaimResult {
  username: string
  nickname: string
}

/** GET /api/qr/sessions/{ticket}/preview 里"要被登录的那台机器" */
export interface QRPCInfo {
  /** 服务端解析过的设备摘要，如 "Chrome · Windows"。不是原始 UA 串 */
  ua: string
  ip: string
  /** IP 粗分类（本机 / 内网 / 公网），best-effort */
  geo: string
  created_at: string
}

/** GET /api/qr/sessions/{ticket}/preview 的 data —— 手机确认页的全部素材 */
export interface QRPreviewResult {
  status: QRStatus
  pc: QRPCInfo
}

/** scan / confirm 的 data */
export interface QRStatusResult {
  status: QRStatus
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
  /** 从未登录过时为 null —— 与「登录过」是两件事，不能用零值时间糊过去 */
  last_login_at: string | null
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

// ══ 注册邀请码 ══════════════════════════════════════════════════════════════

/**
 * 邀请码状态。由后端算好（entity.InvitationCode.Status），
 * 前端**不要**自己从 max_uses / used_count / expires_at 推 ——
 * 推出来的规则一旦与注册接口的放行规则不一致，就会出现
 * 「列表显示可用、注册却被拒」这种自相矛盾的界面。
 */
export type InviteStatus = 'active' | 'disabled' | 'expired' | 'exhausted'

/** GET /api/admin/invites 的行 */
export interface InviteRow {
  id: number
  code: string
  max_uses: number
  used_count: number
  /** 剩余可用次数（后端算好，用完后为 0） */
  remaining: number
  status: InviteStatus
  /** null = 长期有效 */
  expires_at: string | null
  enabled: boolean
  note: string
  created_at: string
  updated_at: string
}

/** 生成邀请码的请求体 */
export interface InviteInput {
  /** 省略或 <=0 时后端取默认值（1 次） */
  max_uses?: number
  /** datetime-local 的值（形如 2026-10-10T15:30）；空串 = 长期有效 */
  expires_at?: string
  note?: string
}

/**
 * 修改邀请码的请求体：**未给出的字段不改**。
 *
 * expires_at 用 undefined 与空串区分两种意图：
 *   undefined → 不改过期时间；"" → 改为长期有效；其他 → 改为该时间。
 * 少了这个区分，"清空过期时间"就与"不动它"无法表达。
 */
export interface InviteUpdateInput {
  max_uses?: number
  expires_at?: string
  enabled?: boolean
  note?: string
}

/** GET /api/admin/invites/:id/usages 的行：一条 = 某次注册用掉了某张码 */
export interface InviteUsageRow {
  id: number
  code: string
  user_id: number
  username: string
  email: string
  used_at: string
}

/** 状态过滤选项（与后端 ListByStatus 接受的取值一致） */
export const INVITE_STATUS_OPTIONS = [
  { value: 'all', label: '全部' },
  { value: 'active', label: '可用' },
  { value: 'disabled', label: '已停用' },
  { value: 'expired', label: '已过期' },
  { value: 'exhausted', label: '已用完' },
] as const

/** 状态 → 展示文案（列表与详情弹窗共用同一份） */
export const INVITE_STATUS_LABEL: Record<InviteStatus, string> = {
  active: '可用',
  disabled: '已停用',
  expired: '已过期',
  exhausted: '已用完',
}

export const TOKEN_STATUS_OPTIONS = [
  { value: 'all', label: '全部' },
  { value: 'active', label: '有效' },
  { value: 'revoked', label: '已吊销' },
]

export const SCOPE_OPTIONS = ['openid', 'profile', 'email']
