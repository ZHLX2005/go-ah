import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { login } from '../api'

/**
 * 登录页 /login
 * - 账号、密码输入 + 前端表单校验
 * - 提交 POST /api/login
 * - 错误提示：账号不存在 / 密码错误
 * - 登录成功后按后端返回的 return_to 回到 OIDC 授权流程
 */
export default function LoginPage() {
  const [sp] = useSearchParams()
  const returnTo = sp.get('return_to') ?? '/oauth2/auth'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')

    // 前端表单校验
    if (!username.trim()) return setError('请输入账号')
    if (!password) return setError('请输入密码')

    setLoading(true)
    try {
      const res = await login(username.trim(), password, returnTo)
      if (res.code === 0 && res.data) {
        // 登录成功 -> 回到 OIDC 授权流程（后端会 302 到授权确认页）
        window.location.href = res.data.return_to
      } else if (res.error === 'user_not_found') {
        setError('账号不存在')
      } else if (res.error === 'wrong_password') {
        setError('密码错误')
      } else {
        setError(res.message || '登录失败，请重试')
      }
    } catch {
      setError('网络异常，请检查 IDP 服务是否已启动')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 px-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-2xl shadow-xl p-8">
          <div className="text-center mb-8">
            <div className="mx-auto w-14 h-14 rounded-xl bg-indigo-600 flex items-center justify-center mb-3">
              <span className="text-white text-2xl font-bold">ID</span>
            </div>
            <h1 className="text-2xl font-bold text-slate-800">统一登录平台</h1>
            <p className="text-sm text-slate-500 mt-1">Identity Provider · OIDC PKCE</p>
          </div>

          <form onSubmit={onSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">账号</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="请输入账号"
                autoComplete="username"
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">密码</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="请输入密码"
                autoComplete="current-password"
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 outline-none transition"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                <span className="shrink-0">⚠</span>
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white font-medium py-2.5 rounded-lg transition"
            >
              {loading ? '登录中…' : '登 录'}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-slate-200">
            <p className="text-xs text-slate-400 text-center mb-2">预置测试账号</p>
            <button
              type="button"
              onClick={() => {
                setUsername('test')
                setPassword('test123456')
              }}
              className="w-full text-sm text-slate-600 bg-slate-100 hover:bg-slate-200 py-2 rounded-lg transition"
            >
              一键填充：test / test123456
            </button>
          </div>
        </div>

        <p className="text-center text-xs text-slate-400 mt-6">
          登录成功后将继续完成 OIDC 授权流程
        </p>
      </div>
    </div>
  )
}
