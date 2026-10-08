import { useEffect, useState } from 'react'
import { fetchUsers, fetchUserSessions, fetchUserTokens, type UserRow, type SessionRow, type RefreshTokenRow } from '../adminApi'
import { PageHeader } from './AdminLayout'

/**
 * 用户管理面板 /admin/users
 * - 用户列表：username、sub、email、创建时间
 * - 展开可查看该用户会话与关联 refresh_token
 */
export default function AdminUsers() {
  const [users, setUsers] = useState<UserRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)
  const [sessions, setSessions] = useState<SessionRow[]>([])
  const [tokens, setTokens] = useState<RefreshTokenRow[]>([])
  const [detailLoading, setDetailLoading] = useState(false)

  useEffect(() => {
    ;(async () => {
      try {
        const res = await fetchUsers()
        if (res.data) setUsers(res.data)
        else setError((res as { message?: string }).message || '加载用户列表失败')
      } catch {
        setError('无法连接 IDP 服务')
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  /** 展开/收起某个用户的详情 */
  async function toggle(id: number) {
    if (expanded === id) {
      setExpanded(null)
      return
    }
    setExpanded(id)
    setDetailLoading(true)
    try {
      const [s, t] = await Promise.all([fetchUserSessions(id), fetchUserTokens(id)])
      setSessions(s.data ?? [])
      setTokens(t.data ?? [])
    } finally {
      setDetailLoading(false)
    }
  }

  return (
    <>
      <PageHeader title="用户管理" desc="统一登录平台的账号列表与会话、令牌关联情况" />
      <div className="p-8">
        {error && <Alert>{error}</Alert>}

        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-5 py-3 text-left font-medium">用户 ID</th>
                <th className="px-5 py-3 text-left font-medium">username</th>
                <th className="px-5 py-3 text-left font-medium">sub</th>
                <th className="px-5 py-3 text-left font-medium">email</th>
                <th className="px-5 py-3 text-left font-medium">角色</th>
                <th className="px-5 py-3 text-left font-medium">创建时间</th>
                <th className="px-5 py-3 text-left font-medium">会话 / 令牌</th>
                <th className="px-5 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={8} className="px-5 py-10 text-center text-slate-400">加载中…</td>
                </tr>
              )}
              {users.map((u) => (
                <>
                  <tr key={u.id} className="hover:bg-slate-50">
                    <td className="px-5 py-3 text-slate-500">{u.id}</td>
                    <td className="px-5 py-3 font-medium text-slate-800">{u.username}</td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-600">{u.id}</td>
                    <td className="px-5 py-3 text-slate-600">{u.email || '-'}</td>
                    <td className="px-5 py-3">
                      {u.is_admin ? (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200">
                          管理员
                        </span>
                      ) : (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 border border-slate-200">
                          普通用户
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs">
                      {new Date(u.created_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3 text-xs">
                      <span className="text-slate-600">会话 {u.session_count}</span>
                      <span className="text-slate-300 mx-1.5">|</span>
                      <span className="text-emerald-600">有效令牌 {u.active_refresh_count}</span>
                      <span className="text-slate-300 mx-1.5">/</span>
                      <span className="text-slate-400">共 {u.refresh_token_count}</span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={() => toggle(u.id)}
                        className="text-xs text-indigo-600 hover:text-indigo-800 font-medium"
                      >
                        {expanded === u.id ? '收起' : '查看详情'}
                      </button>
                    </td>
                  </tr>

                  {expanded === u.id && (
                    <tr key={`${u.id}-detail`} className="bg-slate-50">
                      <td colSpan={8} className="px-5 py-5">
                        {detailLoading ? (
                          <p className="text-xs text-slate-400">加载详情中…</p>
                        ) : (
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                            {/* 会话 */}
                            <div className="bg-white rounded-lg border border-slate-200">
                              <div className="px-4 py-2.5 border-b border-slate-100 text-xs font-semibold text-slate-700">
                                活跃会话（{sessions.length}）
                              </div>
                              <div className="p-3 space-y-2">
                                {sessions.length === 0 && (
                                  <p className="text-xs text-slate-400 py-2">该用户当前无活跃会话</p>
                                )}
                                {sessions.map((s) => (
                                  <div key={s.session_id} className="text-xs bg-slate-50 rounded p-2.5">
                                    <div className="font-mono text-slate-600">{s.session_id}</div>
                                    <div className="text-slate-400 mt-1">
                                      过期：{new Date(s.expires_at).toLocaleString()}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {/* refresh_token */}
                            <div className="bg-white rounded-lg border border-slate-200">
                              <div className="px-4 py-2.5 border-b border-slate-100 text-xs font-semibold text-slate-700">
                                关联 refresh_token（{tokens.length}）
                              </div>
                              <div className="p-3 space-y-2 max-h-64 overflow-y-auto">
                                {tokens.length === 0 && (
                                  <p className="text-xs text-slate-400 py-2">该用户暂无 refresh_token</p>
                                )}
                                {tokens.map((t) => (
                                  <div key={t.id} className="text-xs bg-slate-50 rounded p-2.5">
                                    <div className="flex items-center justify-between">
                                      <span className="font-mono text-slate-600">{t.token}</span>
                                      <StatusBadge token={t} />
                                    </div>
                                    <div className="text-slate-400 mt-1">
                                      {t.client_id} · {t.scope}
                                    </div>
                                    <div className="text-slate-400">
                                      过期：{new Date(t.expires_at).toLocaleString()}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

function StatusBadge({ token }: { token: RefreshTokenRow }) {
  if (token.revoked) {
    return (
      <span className="text-[11px] px-2 py-0.5 rounded-full bg-rose-50 text-rose-600 border border-rose-200">
        已吊销
      </span>
    )
  }
  if (token.expired) {
    return (
      <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 border border-slate-200">
        已过期
      </span>
    )
  }
  return (
    <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-600 border border-emerald-200">
      有效
    </span>
  )
}

function Alert({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
      ⚠ {children}
    </div>
  )
}
