import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { authApi, ApiFailure } from '@/api'
import { parseAuthParams } from '@/api/types'
import type { ConsentInfo } from '@/api/types'
import { hostOf, scopeLabel } from '@/lib/format'
import { errText } from '@/lib/hooks'
import { Alert, Button, Loading } from '@/ui'

/**
 * 授权确认页 /consent
 *
 * 用户在登录页通过后 302 到这里。展示「哪个应用、要哪些权限」，
 * 由用户点同意或拒绝。
 *
 * 两个容易搞错的地方：
 * ① 会话失效（401）时要回到授权入口 /oauth2/auth，而不是 /login ——
 *    授权端点会重新判断并带上完整参数把我们送回来，直接跳 /login 会丢掉这串参数。
 * ② /api/consent 返回的是裸对象（不是统一信封），错误时形如 {error:"..."}，
 *    不能直接当成 ConsentInfo 用，否则渲染 scopes 时会崩。
 */
export default function ConsentPage() {
  const [sp] = useSearchParams()
  const params = parseAuthParams(sp)

  const [info, setInfo] = useState<ConsentInfo | null>(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const d = await authApi.consentInfo(sp)
        if (cancelled) return
        // 裸对象里带 error 字段 = 后端拒绝了这次授权请求
        const maybeErr = (d as unknown as { error?: string })?.error
        if (maybeErr) {
          setErr(`授权请求无效：${maybeErr}`)
          return
        }
        setInfo(d)
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiFailure && e.status === 401) {
          // 会话没了 → 回授权入口重新走一遍（它会再 302 到登录页）
          window.location.href = `/oauth2/auth?${sp.toString()}`
          return
        }
        setErr(errText(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [sp])

  async function decide(decision: 'allow' | 'deny') {
    setErr('')
    setBusy(true)
    try {
      const res = await authApi.submitConsent({ ...params, decision })
      if (res.redirect_to) {
        // 同意 → 带 code 回调业务方；拒绝 → 带 error=access_denied 回调
        window.location.href = res.redirect_to
        return
      }
      setErr(`提交授权失败：${res.error ?? '未知原因'}`)
      setBusy(false)
    } catch (e) {
      setErr(errText(e))
      setBusy(false)
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card auth-card--wide">
        <h1 style={{ fontSize: 19 }}>授权确认</h1>
        <p className="muted" style={{ margin: '4px 0 18px', fontSize: 13 }}>
          第三方应用请求访问你的账号信息
        </p>

        {err !== '' && (
          <div style={{ marginBottom: 16 }}>
            <Alert kind="error">{err}</Alert>
          </div>
        )}

        {info == null && err === '' && <Loading text="正在加载授权信息…" />}

        {info != null && (
          <>
            <div className="grant-box">
              <div className="dim" style={{ fontSize: 12 }}>
                申请授权的应用
              </div>
              <div style={{ fontWeight: 600, marginTop: 2 }}>{info.client_name || '—'}</div>
              <div className="mono dim" style={{ marginTop: 2 }}>
                {info.client_id}
              </div>
            </div>

            <div className="row" style={{ gap: 12, marginTop: 14 }}>
              <span className="avatar">{info.user?.nickname?.[0] ?? 'U'}</span>
              <div style={{ fontSize: 13 }}>
                <div style={{ fontWeight: 500 }}>{info.user?.nickname}</div>
                <div className="dim">
                  {info.user?.username} · {info.user?.email}
                </div>
              </div>
            </div>

            <div style={{ marginTop: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8 }}>
                该应用将获得以下权限
              </div>
              <div className="stack" style={{ gap: 8 }}>
                {info.scopes.map((s) => (
                  <div key={s} className="scope-item">
                    <span className="scope-item__mark">✓</span>
                    <div>
                      <div className="mono" style={{ fontWeight: 500 }}>
                        {s}
                      </div>
                      <div className="dim" style={{ fontSize: 12 }}>
                        {scopeLabel(s)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="row" style={{ gap: 10, marginTop: 24 }}>
              <Button block disabled={busy} onClick={() => void decide('deny')}>
                拒绝授权
              </Button>
              <Button
                block
                variant="primary"
                disabled={busy}
                onClick={() => void decide('allow')}
              >
                {busy ? '处理中…' : '同意授权'}
              </Button>
            </div>

            {params.redirect_uri !== '' && (
              <p className="auth-foot" style={{ marginTop: 16 }}>
                授权后你将跳转回 <span className="mono">{hostOf(params.redirect_uri)}</span>
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}
