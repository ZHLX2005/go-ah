/**
 * API 客户端。
 *
 * 与 gs-ac 控制台的客户端相比，这里有两个不同点：
 *
 * 1. **会话 Cookie 认证**，不是 Bearer。所以每个请求都必须
 *    `credentials: 'include'`，否则 /api/me、/api/admin/* 一律 401。
 *    这也意味着跨域部署时必须配 CORS + 允许凭据，同源（nginx 反代）最省事。
 *
 * 2. **响应形体不统一**。多数接口是 {code, message, error, data} 信封，
 *    但 /api/consent 这类授权流程接口返回的是**裸对象**（前端直接拿它当
 *    client_name / scopes 用）。客户端两种都吃：body 里有 code 字段就当信封解，
 *    否则原样返回。上一版每个页面各写一份 fetch，这层收敛掉了。
 */

const BASE = ''

export class ApiFailure extends Error {
  readonly code: number
  readonly status: number
  /** 后端 error 字段里机器可读的原因，如 user_not_found / wrong_password */
  readonly reason: string

  constructor(message: string, code: number, status: number, reason = '') {
    super(message)
    this.name = 'ApiFailure'
    this.code = code
    this.status = status
    this.reason = reason
  }
}

export interface RequestOptions {
  /** 请求体；GET 时不发 */
  body?: unknown
  /** 查询参数（跳过空值） */
  query?: Record<string, unknown>
  /** 直接用裸 body 字符串（少数接口需要精确控制） */
  rawBody?: string
  /**
   * 返回**整个信封**而不是只返回 data。
   *
   * 少数接口把有用字段放在 data 的**兄弟位置**：创建客户端时后端返回
   * {code, data, client_secret, notice} —— 明文 secret 与 code 同级
   * （见 auth-hub/api/admin.go）。只取 data 会把它整个丢掉，
   * 而这个 secret 只在创建时出现一次，丢了就得重建客户端。
   */
  returnEnvelope?: boolean
}

function buildUrl(path: string, query?: Record<string, unknown>): string {
  if (query == null) return BASE + path
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue
    sp.set(k, String(v))
  }
  const qs = sp.toString()
  return qs ? `${BASE}${path}?${qs}` : BASE + path
}

export async function request<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  const init: RequestInit = { method, headers, credentials: 'include' }

  if (options.rawBody !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = options.rawBody
  } else if (options.body !== undefined && method !== 'GET') {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(options.body)
  }

  let resp: Response
  try {
    resp = await fetch(buildUrl(path, options.query), init)
  } catch (e) {
    throw new ApiFailure(`网络请求失败：${(e as Error).message}`, -1, 0)
  }

  const text = await resp.text()
  let parsed: unknown = null
  if (text !== '') {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
  }

  // 浏览器的 JSON 解析失败（例如网关返回 HTML 错误页）
  if (parsed === null && text !== '' && resp.ok) {
    throw new ApiFailure(
      `响应不是 JSON（HTTP ${resp.status}）：${text.slice(0, 200)}`,
      resp.status,
      resp.status,
    )
  }

  const body = (parsed ?? {}) as Record<string, unknown>

  // 统一信封：body 里带 code 就走信封语义
  if ('code' in body) {
    const code = typeof body.code === 'number' ? body.code : -1
    if (code !== 0) {
      const reason = typeof body.error === 'string' ? body.error : ''
      const message =
        (typeof body.message === 'string' && body.message) ||
        (typeof body.error === 'string' && body.error) ||
        `请求失败（code=${code}）`
      throw new ApiFailure(message, code, resp.status, reason)
    }
    return (options.returnEnvelope === true ? body : (body.data ?? null)) as T
  }

  // 非信封（/api/consent 等）：HTTP 状态即结果
  if (!resp.ok) {
    // 401/403 是管理台最常见的两种，给出明确文案而不是干巴巴的状态码
    const hint =
      resp.status === 401 ? '未登录或会话已过期' : resp.status === 403 ? '当前账号无此权限' : ''
    throw new ApiFailure(hint || `HTTP ${resp.status}`, resp.status, resp.status)
  }
  return body as T
}

export const http = {
  get: <T>(path: string, query?: Record<string, unknown>) => request<T>('GET', path, { query }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, { body }),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, { body }),
  del: <T>(path: string) => request<T>('DELETE', path),
}
