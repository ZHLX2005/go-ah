import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { parseAuthParams, type ConsentInfo } from '../types'
import { submitConsent } from '../api'

/** scope 中文说明，便于用户理解授权范围 */
const SCOPE_LABEL: Record<string, string> = {
  openid: '获取你的唯一身份标识 (sub)',
  profile: '获取你的基本资料（昵称、用户名）',
  email: '获取你的邮箱地址',
}

/**
 * 授权确认页 /consent
 * - 展示申请授权的应用名称与 scope
 * - 【同意授权】-> 后端生成 authorization code，302 回调业务 redirect_uri
 * - 【拒绝授权】-> 回调业务并携带 error=access_denied
 */
export default function ConsentPage() {
  const [sp] = useSearchParams()
  const params = parseAuthParams(sp)

  const [info, setInfo] = useState<ConsentInfo | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  // 加载授权确认展示数据；若会话失效则回到授权入口重新登录
  useEffect(() => {
    let cancelled = false
    fetch(`/api/consent?${sp.toString()}`, { credentials: 'include' })
      .then(async (r) => {
        const d = await r.json()
        if (cancelled) return
        if (r.status === 401) {
          window.location.href = `/oauth2/auth?${sp.toString()}`
          return
        }
        if (d.error) {
          setError('授权请求无效：' + d.error)
          return
        }
        setInfo(d as ConsentInfo)
      })
      .catch(() => !cancelled && setError('加载授权信息失败'))
    return () => {
      cancelled = true
    }
  }, [sp])

  async function decide(decision: 'allow' | 'deny') {
    setError('')
    setLoading(true)
    try {
      const res = await submitConsent({ ...params, decision })
      if ('redirect_to' in res && res.redirect_to) {
        // 同意：带 code 回调业务；拒绝：带 error 回调业务
        window.location.href = res.redirect_to
      } else {
        setError('提交授权失败：' + (('error' in res && res.error) || 'unknown'))
        setLoading(false)
      }
    } catch {
      setError('网络异常，请重试')
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 px-4">
      <div className="w-full max-w-lg">
        <div className="bg-white rounded-2xl shadow-xl p-8">
          <div className="text-center mb-6">
            <div className="mx-auto w-14 h-14 rounded-xl bg-amber-500 flex items-center justify-center mb-3">
              <span className="text-white text-2xl">🔐</span>
            </div>
            <h1 className="text-xl font-bold text-slate-800">授权确认</h1>
            <p className="text-sm text-slate-500 mt-1">第三方应用请求访问你的账号信息</p>
          </div>

          {error && (
            <div className="mb-5 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
              ⚠ {error}
            </div>
          )}

          {!info && !error && (
            <div className="text-center py-10 text-slate-400 text-sm">正在加载授权信息…</div>
          )}

          {info && (
            <>
              {/* 申请方 */}
              <div className="bg-slate-50 rounded-xl p-4 mb-5">
                <div className="text-xs text-slate-400 mb-1">申请授权的应用</div>
                <div className="font-semibold text-slate-800">{info.client_name}</div>
                <div className="text-xs text-slate-400 mt-0.5 font-mono">{info.client_id}</div>
              </div>

              {/* 当前账号 */}
              <div className="flex items-center gap-3 bg-indigo-50 rounded-xl p-4 mb-5">
                <div className="w-10 h-10 rounded-full bg-indigo-600 text-white flex items-center justify-center font-semibold">
                  {info.user.nickname?.[0] ?? 'U'}
                </div>
                <div className="text-sm">
                  <div className="font-medium text-slate-800">{info.user.nickname}</div>
                  <div className="text-slate-500">
                    {info.user.username} · {info.user.email}
                  </div>
                </div>
              </div>

              {/* scope 列表 */}
              <div className="mb-6">
                <div className="text-sm font-medium text-slate-700 mb-2">该应用将获得以下权限</div>
                <ul className="space-y-2">
                  {info.scopes.map((s) => (
                    <li key={s} className="flex items-start gap-3 bg-white border border-slate-200 rounded-lg px-4 py-3">
                      <span className="text-emerald-500 mt-0.5">✓</span>
                      <div>
                        <div className="text-sm font-medium text-slate-800 font-mono">{s}</div>
                        <div className="text-xs text-slate-500">{SCOPE_LABEL[s] ?? '自定义权限范围'}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="flex gap-3">
                <button
                  disabled={loading}
                  onClick={() => decide('deny')}
                  className="flex-1 border border-slate-300 text-slate-700 hover:bg-slate-50 disabled:opacity-50 font-medium py-2.5 rounded-lg transition"
                >
                  拒绝授权
                </button>
                <button
                  disabled={loading}
                  onClick={() => decide('allow')}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white font-medium py-2.5 rounded-lg transition"
                >
                  {loading ? '处理中…' : '同意授权'}
                </button>
              </div>

              <p className="text-xs text-slate-400 text-center mt-5">
                授权后你将跳转回 <span className="font-mono">{new URL(params.redirect_uri).host}</span>
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
