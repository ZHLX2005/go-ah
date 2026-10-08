import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { authApi } from '@/api'
import { Alert, Button } from '@/ui'

/**
 * 登出确认页 /logout（RP-Initiated Logout）
 *
 * 业务方或本平台都可以把用户带到这里。确认后：
 *   ① 销毁 IDP 全局会话
 *   ② 吊销该用户**全部** refresh_token（后端一并做）
 *   ③ 跳回 post_logout_redirect_uri，并把 state 原样带上
 *
 * 为什么要有确认这一步：登出是「一次登出、所有接入应用全部失效」的破坏性动作，
 * 直接执行会让用户误点一下就断掉全部在线应用。
 */
export default function LogoutPage() {
  const [sp] = useSearchParams()
  const postLogout = sp.get('post_logout_redirect_uri') ?? ''
  const state = sp.get('state') ?? ''

  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  async function confirmLogout() {
    setBusy(true)
    try {
      await authApi.logout(postLogout, state)
    } catch {
      // 即使请求异常也继续跳转 —— 用户已经点了登出，
      // 把他卡在「登出中」页面上比多跳一次更糟
    }
    setDone(true)

    if (postLogout !== '') {
      let target = postLogout
      try {
        const url = new URL(postLogout)
        if (state !== '') url.searchParams.set('state', state)
        target = url.toString()
      } catch {
        // 不是合法 URL 就原样跳，交给浏览器报错，比静默不动好
      }
      window.setTimeout(() => {
        window.location.href = target
      }, 800)
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card" style={{ textAlign: 'center' }}>
        {done ? (
          <>
            <h1 style={{ fontSize: 19 }}>已退出登录</h1>
            <p className="muted" style={{ fontSize: 13, marginTop: 6 }}>
              全局会话已销毁，该账号的全部刷新令牌已吊销。
            </p>
            {postLogout !== '' && (
              <p className="auth-foot" style={{ marginTop: 16 }}>
                正在跳转回应用… 若无跳转请
                <a href={postLogout} style={{ marginLeft: 4 }}>
                  点击这里
                </a>
              </p>
            )}
          </>
        ) : (
          <>
            <h1 style={{ fontSize: 19 }}>确认退出登录？</h1>
            <p className="muted" style={{ fontSize: 13, marginTop: 6, lineHeight: 1.8 }}>
              退出后将结束你的<b>全局账号会话</b>，所有已授权应用都需要重新登录。
            </p>

            <div style={{ marginTop: 16, textAlign: 'left' }}>
              <Alert>这一步会同时吊销该账号在当前认证中心上的全部 refresh_token。</Alert>
            </div>

            <div className="row" style={{ gap: 10, marginTop: 24 }}>
              <Button block disabled={busy} onClick={() => history.back()}>
                取消
              </Button>
              <Button block variant="danger" disabled={busy} onClick={() => void confirmLogout()}>
                {busy ? '退出中…' : '确认登出'}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
