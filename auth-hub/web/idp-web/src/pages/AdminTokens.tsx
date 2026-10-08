import { useEffect, useState } from 'react'
import { fetchRefreshTokens, revokeToken, type RefreshTokenRow } from '../adminApi'
import { PageHeader } from './AdminLayout'

/**
 * Token 管理面板 /admin/tokens
 * - 列出 refresh_token：user_sub、client_id、scope、过期时间、revoked 标记
 * - 【吊销】按钮：调用 /api/admin/revoke-token 写入 revoked 标记
 */
export default function AdminTokens() {
  const [tokens, setTokens] = useState<RefreshTokenRow[]>([])
  const [status, setStatus] = useState<'all' | 'active' | 'revoked'>('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busyId, setBusyId] = useState<number | null>(null)

  async function load(s: string = status) {
    setLoading(true)
    setError('')
    try {
      const res = await fetchRefreshTokens(s)
      if (res.data) setTokens(res.data)
      else setError('加载令牌列表失败')
    } catch {
      setError('无法连接 IDP 服务')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load(status)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status])

  /** 吊销单个 refresh_token */
  async function onRevoke(t: RefreshTokenRow) {
    if (!confirm(`确认吊销该 refresh_token？\n用户：${t.username || t.user_sub}\n客户端：${t.client_id}`)) return
    setBusyId(t.id)
    setNotice('')
    try {
      const res = await revokeToken(t.id)
      if (res.__status !== 200) {
        setError((res as { message?: string }).message || '吊销失败')
        return
      }
      setNotice(`已吊销 refresh_token #${t.id}（用户 ${t.username || t.user_sub}）`)
      await load()
    } finally {
      setBusyId(null)
    }
  }

  const activeCount = tokens.filter((t) => !t.revoked && !t.expired).length
  const revokedCount = tokens.filter((t) => t.revoked).length

  return (
    <>
      <PageHeader
        title="Token 管理"
        desc="refresh_token 全量视图；吊销后该令牌立即失效，关联会话需重新登录"
        action={
          <button
            onClick={() => load()}
            className="border border-slate-300 text-slate-600 hover:bg-slate-50 text-sm font-medium px-4 py-2 rounded-lg transition"
          >
            ↻ 刷新
          </button>
        }
      />

      <div className="p-8 space-y-5">
        {error && <Alert kind="red">{error}</Alert>}
        {notice && <Alert kind="emerald">{notice}</Alert>}

        {/* 统计 + 过滤 */}
        <div className="flex flex-wrap items-center gap-3">
          <Stat label="当前视图总数" value={tokens.length} />
          <Stat label="有效" value={activeCount} tone="emerald" />
          <Stat label="已吊销" value={revokedCount} tone="rose" />

          <div className="ml-auto flex gap-1 bg-white rounded-lg p-1 shadow-sm border border-slate-200">
            {(['all', 'active', 'revoked'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatus(s)}
                className={`text-xs px-3.5 py-1.5 rounded-md transition ${
                  status === s ? 'bg-indigo-600 text-white' : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                {s === 'all' ? '全部' : s === 'active' ? '仅有效' : '仅已吊销'}
              </button>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-5 py-3 text-left font-medium">ID</th>
                <th className="px-5 py-3 text-left font-medium">token</th>
                <th className="px-5 py-3 text-left font-medium">user_sub</th>
                <th className="px-5 py-3 text-left font-medium">用户名</th>
                <th className="px-5 py-3 text-left font-medium">client_id</th>
                <th className="px-5 py-3 text-left font-medium">scope</th>
                <th className="px-5 py-3 text-left font-medium">过期时间</th>
                <th className="px-5 py-3 text-center font-medium">revoked</th>
                <th className="px-5 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={9} className="px-5 py-10 text-center text-slate-400">加载中…</td>
                </tr>
              )}
              {!loading && tokens.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-5 py-10 text-center text-slate-400">
                    暂无 refresh_token。先到业务平台或 CLI 完成一次登录即可产生。
                  </td>
                </tr>
              )}
              {tokens.map((t) => (
                <tr key={t.id} className={`hover:bg-slate-50 ${t.revoked ? 'opacity-60' : ''}`}>
                  <td className="px-5 py-3 text-slate-500">{t.id}</td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-600">{t.token}</td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-600">{t.user_sub}</td>
                  <td className="px-5 py-3 text-slate-700">{t.username || '-'}</td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-600">{t.client_id}</td>
                  <td className="px-5 py-3 text-xs text-slate-500">{t.scope}</td>
                  <td className="px-5 py-3 text-xs text-slate-500">
                    {new Date(t.expires_at).toLocaleString()}
                  </td>
                  <td className="px-5 py-3 text-center">
                    {t.revoked ? (
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-rose-50 text-rose-600 border border-rose-200">
                        true
                      </span>
                    ) : (
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-600 border border-emerald-200">
                        false
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button
                      disabled={t.revoked || busyId === t.id}
                      onClick={() => onRevoke(t)}
                      className="text-xs font-medium px-3 py-1.5 rounded-lg border transition disabled:opacity-40 disabled:cursor-not-allowed border-rose-200 text-rose-600 hover:bg-rose-50"
                    >
                      {busyId === t.id ? '吊销中…' : '吊销'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: 'emerald' | 'rose' }) {
  const color = tone === 'emerald' ? 'text-emerald-600' : tone === 'rose' ? 'text-rose-600' : 'text-slate-800'
  return (
    <div className="bg-white rounded-lg shadow-sm border border-slate-200 px-4 py-2.5">
      <div className="text-[11px] text-slate-400">{label}</div>
      <div className={`text-lg font-semibold ${color}`}>{value}</div>
    </div>
  )
}

function Alert({ kind, children }: { kind: 'red' | 'emerald'; children: React.ReactNode }) {
  const map = {
    red: 'bg-red-50 border-red-200 text-red-700',
    emerald: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  }
  return <div className={`border rounded-lg px-4 py-3 text-sm ${map[kind]}`}>{children}</div>
}
