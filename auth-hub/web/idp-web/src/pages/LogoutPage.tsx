import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * 登出确认页 /logout
 * - 提示确认退出全局账号会话
 * - 确认登出：销毁 IDP 会话 + 吊销该用户全部 refresh_token
 * - 完成后跳转 post_logout_redirect_uri
 *
 * 参数：post_logout_redirect_uri、state（由业务方或 IDP 登出入口传入）
 */
export default function LogoutPage() {
  const [sp] = useSearchParams()
  const postLogout = sp.get('post_logout_redirect_uri') ?? ''
  const state = sp.get('state') ?? ''

  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  async function confirmLogout() {
    setLoading(true)
    try {
      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_logout_redirect_uri: postLogout, state }),
      })
    } catch {
      /* 即使请求异常也继续跳转，避免用户卡死 */
    }
    setDone(true)
    if (postLogout) {
      const url = new URL(postLogout)
      if (state) url.searchParams.set('state', state)
      setTimeout(() => (window.location.href = url.toString()), 800)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl p-8 text-center">
        <div className="mx-auto w-14 h-14 rounded-xl bg-rose-500 flex items-center justify-center mb-4">
          <span className="text-white text-2xl">⏏</span>
        </div>

        {done ? (
          <>
            <h1 className="text-xl font-bold text-slate-800">已退出登录</h1>
            <p className="text-sm text-slate-500 mt-2">全局会话已销毁，令牌已吊销</p>
            {postLogout && (
              <p className="text-xs text-slate-400 mt-4">
                正在跳转回应用… 若无跳转请
                <a className="text-indigo-600 underline ml-1" href={postLogout}>
                  点击这里
                </a>
              </p>
            )}
          </>
        ) : (
          <>
            <h1 className="text-xl font-bold text-slate-800">确认退出登录？</h1>
            <p className="text-sm text-slate-500 mt-2">
              退出后将结束你的<b>全局账号会话</b>，所有已授权应用都需要重新登录。
            </p>

            <div className="flex gap-3 mt-7">
              <button
                onClick={() => history.back()}
                className="flex-1 border border-slate-300 text-slate-700 hover:bg-slate-50 font-medium py-2.5 rounded-lg transition"
              >
                取消
              </button>
              <button
                disabled={loading}
                onClick={confirmLogout}
                className="flex-1 bg-rose-600 hover:bg-rose-700 disabled:bg-rose-400 text-white font-medium py-2.5 rounded-lg transition"
              >
                {loading ? '退出中…' : '确认登出'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
