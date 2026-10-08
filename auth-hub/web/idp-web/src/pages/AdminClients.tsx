import { useEffect, useState, type FormEvent } from 'react'
import { fetchClients, createClient, updateClient, deleteClient, type ClientRow } from '../adminApi'
import { PageHeader } from './AdminLayout'

/**
 * OIDC 客户端管理 /admin/clients
 * - 列表：client_id、redirect_uris、scopes、pkce_required、enabled
 * - 新增：自动生成 client_secret（机密客户端）、PKCE 开关、多回调地址录入
 * - 编辑、删除
 */
export default function AdminClients() {
  const [clients, setClients] = useState<ClientRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  // 新建表单
  const [showForm, setShowForm] = useState(false)
  const [clientId, setClientId] = useState('')
  const [clientName, setClientName] = useState('')
  const [redirects, setRedirects] = useState('')
  const [scopes, setScopes] = useState('openid profile email')
  const [isPublic, setIsPublic] = useState(true)
  const [pkceRequired, setPkceRequired] = useState(true)
  const [postLogout, setPostLogout] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [newSecret, setNewSecret] = useState('')

  // 编辑态
  const [editing, setEditing] = useState<ClientRow | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await fetchClients()
      if (res.data) setClients(res.data)
      else setError('加载客户端列表失败')
    } catch {
      setError('无法连接 IDP 服务')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  /** 提交新建 */
  async function onCreate(e: FormEvent) {
    e.preventDefault()
    setError('')
    setNewSecret('')
    setSubmitting(true)
    try {
      const res = await createClient({
        client_id: clientId.trim(),
        client_name: clientName.trim(),
        redirect_uris: redirects.split('\n').map((s) => s.trim()).filter(Boolean),
        scopes: scopes.split(/\s+/).filter(Boolean),
        post_logout_uris: postLogout.split('\n').map((s) => s.trim()).filter(Boolean),
        is_public: isPublic,
        pkce_required: isPublic ? true : pkceRequired,
      })
      if (res.__status !== 200) {
        setError((res as { message?: string }).message || '创建失败')
        return
      }
      if (res.client_secret) {
        setNewSecret(res.client_secret)
      }
      setNotice(`客户端 ${clientId} 创建成功`)
      setClientId('')
      setClientName('')
      setRedirects('')
      setPostLogout('')
      setShowForm(false)
      await load()
    } finally {
      setSubmitting(false)
    }
  }

  /** 切换启用状态 */
  async function toggleEnabled(c: ClientRow) {
    await updateClient(c.id, { enabled: !c.enabled })
    await load()
  }

  /** 保存编辑 */
  async function saveEdit(e: FormEvent) {
    e.preventDefault()
    if (!editing) return
    setSubmitting(true)
    try {
      const res = await updateClient(editing.id, {
        client_name: editing.client_name,
        redirect_uris: editing.redirect_uris,
        scopes: editing.scopes,
        pkce_required: editing.is_public ? true : editing.pkce_required,
        post_logout_uris: editing.post_logout_uris,
      })
      if (res.__status !== 200) {
        setError((res as { message?: string }).message || '更新失败')
        return
      }
      setNotice('客户端已更新')
      setEditing(null)
      await load()
    } finally {
      setSubmitting(false)
    }
  }

  /** 删除 */
  async function onDelete(c: ClientRow) {
    if (!confirm(`确认删除客户端 ${c.client_id}？该操作会同时清理其令牌。`)) return
    const res = await deleteClient(c.id)
    if (res.__status !== 200) {
      setError((res as { message?: string }).message || '删除失败')
      return
    }
    setNotice(`客户端 ${c.client_id} 已删除`)
    await load()
  }

  return (
    <>
      <PageHeader
        title="OIDC 客户端管理"
        desc="注册在统一登录平台的业务客户端（PKCE 公共客户端 / 机密客户端）"
        action={
          <button
            onClick={() => setShowForm((v) => !v)}
            className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition"
          >
            {showForm ? '取消' : '+ 新增客户端'}
          </button>
        }
      />

      <div className="p-8 space-y-5">
        {error && <Alert kind="red">{error}</Alert>}
        {notice && <Alert kind="emerald">{notice}</Alert>}
        {newSecret && (
          <Alert kind="amber">
            <b>client_secret（仅显示这一次，请立即保存）：</b>
            <div className="mt-2 font-mono text-xs bg-white/60 rounded px-3 py-2 break-all">{newSecret}</div>
          </Alert>
        )}

        {/* 新建表单 */}
        {showForm && (
          <form onSubmit={onCreate} className="bg-white rounded-xl shadow-sm p-6 space-y-4">
            <h3 className="font-semibold text-slate-800 text-sm">新增 OIDC 客户端</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="client_id *">
                <input
                  required
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  placeholder="my-app-client"
                  className="input"
                />
              </Field>
              <Field label="应用名称">
                <input
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  placeholder="我的业务应用"
                  className="input"
                />
              </Field>
            </div>

            <Field label="回调地址（每行一个）*">
              <textarea
                required
                rows={3}
                value={redirects}
                onChange={(e) => setRedirects(e.target.value)}
                placeholder={'http://127.0.0.1:9000/oauth/callback\nhttp://127.0.0.1:*/callback'}
                className="input font-mono text-xs"
              />
              <p className="text-[11px] text-slate-400 mt-1">
                端口通配（http://127.0.0.1:*/callback）仅支持回环地址，用于 CLI 等自动分配端口的本机客户端
              </p>
            </Field>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="scope（空格分隔）">
                <input value={scopes} onChange={(e) => setScopes(e.target.value)} className="input font-mono text-xs" />
              </Field>
              <Field label="登出后回调地址（每行一个）">
                <textarea
                  rows={2}
                  value={postLogout}
                  onChange={(e) => setPostLogout(e.target.value)}
                  placeholder="http://127.0.0.1:9000/"
                  className="input font-mono text-xs"
                />
              </Field>
            </div>

            <div className="flex flex-wrap items-center gap-6 pt-1">
              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input type="checkbox" checked={isPublic} onChange={(e) => setIsPublic(e.target.checked)} className="rounded" />
                公共客户端（无 client_secret，强制 PKCE）
              </label>
              <label className={`flex items-center gap-2 text-sm ${isPublic ? 'text-slate-300' : 'text-slate-700'}`}>
                <input
                  type="checkbox"
                  checked={isPublic ? true : pkceRequired}
                  disabled={isPublic}
                  onChange={(e) => setPkceRequired(e.target.checked)}
                  className="rounded"
                />
                要求 PKCE
              </label>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={submitting}
                className="bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white text-sm font-medium px-6 py-2.5 rounded-lg transition"
              >
                {submitting ? '创建中…' : '创建客户端'}
              </button>
            </div>
          </form>
        )}

        {/* 编辑表单 */}
        {editing && (
          <form onSubmit={saveEdit} className="bg-amber-50 border border-amber-200 rounded-xl p-6 space-y-4">
            <h3 className="font-semibold text-slate-800 text-sm">
              编辑客户端：<span className="font-mono">{editing.client_id}</span>
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="应用名称">
                <input
                  value={editing.client_name}
                  onChange={(e) => setEditing({ ...editing, client_name: e.target.value })}
                  className="input"
                />
              </Field>
              <Field label="scope（空格分隔）">
                <input
                  value={editing.scopes.join(' ')}
                  onChange={(e) => setEditing({ ...editing, scopes: e.target.value.split(/\s+/).filter(Boolean) })}
                  className="input font-mono text-xs"
                />
              </Field>
            </div>
            <Field label="回调地址（每行一个）">
              <textarea
                rows={3}
                value={editing.redirect_uris.join('\n')}
                onChange={(e) =>
                  setEditing({ ...editing, redirect_uris: e.target.value.split('\n').map((s) => s.trim()).filter(Boolean) })
                }
                className="input font-mono text-xs"
              />
            </Field>
            <Field label="登出后回调地址（每行一个）">
              <textarea
                rows={2}
                value={editing.post_logout_uris.join('\n')}
                onChange={(e) =>
                  setEditing({ ...editing, post_logout_uris: e.target.value.split('\n').map((s) => s.trim()).filter(Boolean) })
                }
                className="input font-mono text-xs"
              />
            </Field>
            <div className="flex gap-3">
              <button
                type="submit"
                disabled={submitting}
                className="bg-amber-600 hover:bg-amber-700 disabled:bg-amber-400 text-white text-sm font-medium px-5 py-2 rounded-lg transition"
              >
                {submitting ? '保存中…' : '保存修改'}
              </button>
              <button
                type="button"
                onClick={() => setEditing(null)}
                className="border border-slate-300 text-slate-600 hover:bg-white text-sm font-medium px-5 py-2 rounded-lg transition"
              >
                取消
              </button>
            </div>
          </form>
        )}

        {/* 列表 */}
        <div className="bg-white rounded-xl shadow-sm overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-xs uppercase">
              <tr>
                <th className="px-5 py-3 text-left font-medium">client_id</th>
                <th className="px-5 py-3 text-left font-medium">应用名称</th>
                <th className="px-5 py-3 text-left font-medium">回调地址</th>
                <th className="px-5 py-3 text-left font-medium">scopes</th>
                <th className="px-5 py-3 text-center font-medium">PKCE</th>
                <th className="px-5 py-3 text-center font-medium">状态</th>
                <th className="px-5 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && (
                <tr>
                  <td colSpan={7} className="px-5 py-10 text-center text-slate-400">加载中…</td>
                </tr>
              )}
              {clients.map((c) => (
                <tr key={c.id} className="hover:bg-slate-50 align-top">
                  <td className="px-5 py-4">
                    <div className="font-mono text-xs text-slate-800">{c.client_id}</div>
                    <div className="text-[11px] text-slate-400 mt-1">
                      {c.is_public ? '公共客户端' : '机密客户端'}
                      {c.has_secret && ' · 已配置密钥'}
                    </div>
                  </td>
                  <td className="px-5 py-4 text-slate-700">{c.client_name || '-'}</td>
                  <td className="px-5 py-4">
                    {c.redirect_uris.map((u) => (
                      <div key={u} className="font-mono text-[11px] text-slate-500 break-all">{u}</div>
                    ))}
                  </td>
                  <td className="px-5 py-4">
                    <div className="flex flex-wrap gap-1">
                      {c.scopes.map((s) => (
                        <span key={s} className="text-[11px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-5 py-4 text-center">
                    {c.pkce_required ? (
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-600 border border-indigo-200">
                        必需
                      </span>
                    ) : (
                      <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-400 border border-slate-200">
                        可选
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-4 text-center">
                    <button
                      onClick={() => toggleEnabled(c)}
                      className={`text-[11px] px-2.5 py-1 rounded-full border transition ${
                        c.enabled
                          ? 'bg-emerald-50 text-emerald-600 border-emerald-200 hover:bg-emerald-100'
                          : 'bg-slate-100 text-slate-400 border-slate-200 hover:bg-slate-200'
                      }`}
                    >
                      {c.enabled ? '已启用' : '已禁用'}
                    </button>
                  </td>
                  <td className="px-5 py-4 text-right whitespace-nowrap">
                    <button
                      onClick={() => setEditing(c)}
                      className="text-xs text-indigo-600 hover:text-indigo-800 font-medium mr-3"
                    >
                      编辑
                    </button>
                    <button
                      onClick={() => onDelete(c)}
                      className="text-xs text-rose-600 hover:text-rose-800 font-medium"
                    >
                      删除
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

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-slate-600 mb-1.5">{label}</label>
      {children}
    </div>
  )
}

function Alert({ kind, children }: { kind: 'red' | 'emerald' | 'amber'; children: React.ReactNode }) {
  const map = {
    red: 'bg-red-50 border-red-200 text-red-700',
    emerald: 'bg-emerald-50 border-emerald-200 text-emerald-700',
    amber: 'bg-amber-50 border-amber-200 text-amber-800',
  }
  return <div className={`border rounded-lg px-4 py-3 text-sm ${map[kind]}`}>{children}</div>
}
