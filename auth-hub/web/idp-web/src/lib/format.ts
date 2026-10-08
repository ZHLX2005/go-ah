/** 展示层格式化工具。都是纯函数，不依赖 React。 */

/**
 * 后端时间串 → 紧凑展示。
 * 后端用 "YYYY-MM-DD HH:mm:ss"（空格分隔），Safari 对该格式解析不稳，统一换成 T。
 * 零值（0001-01-01）视为「无」—— 数据库里未设置的 time 字段就是这个值，
 * 直接显示会给用户看到一串没意义的远古时间。
 */
export function fmtTime(v?: string | null): string {
  if (!v) return '—'
  const s = v.trim()
  if (s === '' || s.startsWith('0001-01-01')) return '—'
  const normalized = s.includes('T') ? s : s.replace(' ', 'T')
  const d = new Date(normalized)
  if (Number.isNaN(d.getTime())) return s
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/** 只有日期 */
export function fmtDate(v?: string | null): string {
  const t = fmtTime(v)
  return t === '—' ? t : t.slice(0, 10)
}

/** 长串中间省略：token / session_id 这类在高表里必须截断，否则表格被撑爆 */
export function truncMiddle(s?: string | null, head = 10, tail = 6): string {
  if (!s) return '—'
  if (s.length <= head + tail + 1) return s
  return `${s.slice(0, head)}…${s.slice(-tail)}`
}

/** 逗号/换行分隔的多值输入 → 数组（去空白、去空项、去重） */
export function parseList(input: string): string[] {
  return Array.from(
    new Set(
      input
        .split(/[,\n]/)
        .map((t) => t.trim())
        .filter((t) => t !== ''),
    ),
  )
}

export function joinList(items?: string[] | null): string {
  return (items ?? []).join('\n')
}

export function clampText(s?: string | null, max = 80): string {
  if (!s) return '—'
  const one = s.replace(/\s+/g, ' ').trim()
  return one.length > max ? `${one.slice(0, max)}…` : one
}

/** scope 说明：授权确认页与管理台共用同一份文案，避免两处说法不一致 */
export const SCOPE_LABEL: Record<string, string> = {
  openid: '获取你的唯一身份标识 (sub)',
  profile: '获取你的基本资料（昵称、用户名）',
  email: '获取你的邮箱地址',
}

export function scopeLabel(scope: string): string {
  return SCOPE_LABEL[scope] ?? '自定义权限范围'
}

/** 从 URI 里取 host，用于「授权后将跳转回 X」这类提示 */
export function hostOf(uri: string): string {
  try {
    return new URL(uri).host
  } catch {
    return uri
  }
}
