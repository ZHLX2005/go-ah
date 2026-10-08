import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { exchangeCode } from '../api'
import { takeStoredPkce } from '../oidc'

/**
 * OIDC 回调页 /oauth/callback
 *
 * 页面加载时执行：
 *   1) 从 URL 捕获 code、state（以及可能的 error）
 *   2) 校验 state 与 sessionStorage 中保存的一致（防 CSRF）
 *   3) 取出 code_verifier，连同 code 一起 POST 给业务后端
 *   4) 业务后端完成 token 交换、id_token 校验、建立业务会话（设置 Cookie）
 *   5) 成功后自动跳转首页
 *
 * 处理失败时展示明确错误：授权拒绝 / state 不匹配 / code 失效等
 */
export default function CallbackPage() {
  const [sp] = useSearchParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState<'loading' | 'error'>('loading')
  const [message, setMessage] = useState('正在处理授权回调…')
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true

    ;(async () => {
      const code = sp.get('code')
      const returnedState = sp.get('state')
      const errParam = sp.get('error')
      const errDesc = sp.get('error_description')

      // ---- 情况 1：IDP 直接返回错误（用户拒绝授权等） ----
      if (errParam) {
        setStatus('error')
        setMessage(
          errParam === 'access_denied'
            ? '你已拒绝授权，无法登录业务平台。'
            : `授权失败：${errParam}${errDesc ? ' - ' + errDesc : ''}`,
        )
        return
      }

      if (!code) {
        setStatus('error')
        setMessage('回调地址缺少 code 参数，无法完成登录。')
        return
      }

      // ---- 情况 2：取回本地 PKCE 状态并校验 state ----
      const stored = takeStoredPkce()
      if (!stored) {
        setStatus('error')
        setMessage('未找到本地 PKCE 状态（sessionStorage 为空），请从首页重新发起登录。')
        return
      }
      if (stored.state !== returnedState) {
        setStatus('error')
        setMessage('state 校验失败，可能存在 CSRF 风险，已终止本次授权。')
        return
      }

      // ---- 情况 3：提交 code + code_verifier 给业务后端 ----
      setMessage('正在与统一登录平台交换令牌…')
      try {
        const res = await exchangeCode({
          code,
          state: returnedState ?? '',
          code_verifier: stored.code_verifier,
          redirect_uri: stored.redirect_uri,
        })

        if (res.code === 0) {
          setMessage('登录成功，正在跳转首页…')
          setTimeout(() => navigate('/', { replace: true }), 600)
          return
        }

        // 错误分类展示，便于排查
        const hint =
          res.error === 'token_exchange_failed'
            ? '授权码可能已失效、已被使用，或 code_verifier 不匹配（PKCE 校验失败）。'
            : res.error === 'invalid_id_token'
              ? 'id_token 校验未通过（iss / aud / exp / 签名）。'
              : res.message ?? res.error ?? '未知错误'
        setStatus('error')
        setMessage(`登录失败：${hint}`)
      } catch {
        setStatus('error')
        setMessage('无法连接业务后端，请确认服务已启动。')
      }
    })()
  }, [sp, navigate])

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl p-8 text-center">
        {status === 'loading' ? (
          <>
            <div className="mx-auto w-10 h-10 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin" />
            <h1 className="text-lg font-semibold text-slate-700 mt-5">OIDC 授权回调中</h1>
            <p className="text-sm text-slate-500 mt-2">{message}</p>
            <div className="mt-6 text-left text-xs text-slate-400 bg-slate-50 rounded-lg p-4 space-y-1">
              <div>1. 捕获 code / state</div>
              <div>2. 校验 state 防 CSRF</div>
              <div>3. 提交 code + code_verifier 至业务后端</div>
              <div>4. 后端交换 token 并校验 id_token</div>
              <div>5. 建立业务会话后跳转首页</div>
            </div>
          </>
        ) : (
          <>
            <div className="mx-auto w-12 h-12 rounded-xl bg-red-100 text-red-600 flex items-center justify-center text-2xl">
              ⚠
            </div>
            <h1 className="text-lg font-semibold text-slate-800 mt-4">授权未完成</h1>
            <p className="text-sm text-slate-600 mt-2">{message}</p>
            <button
              onClick={() => navigate('/', { replace: true })}
              className="mt-6 w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 rounded-lg transition"
            >
              返回首页重新登录
            </button>
          </>
        )}
      </div>
    </div>
  )
}
