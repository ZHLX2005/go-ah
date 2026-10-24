import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { authApi } from '@/api'
import type { UserInfo } from '@/api'
import { Loading } from '@/ui'

/**
 * 登录成功落地页 /welcome
 *
 * 扫码/口令登录建立的是**统一登录平台自己的会话**（idp_session），
 * 与任何接入方无关。没有业务方上下文时（直接打开登录平台、扫码成功），
 * 落到这里展示"你是谁、已登录"，而不是被塞进 /oauth2/auth ——
 * 授权端点天生要求 client_id，把它当登录后的落点，用户看到的
 * 就是一句莫名其妙的 invalid client_id（扫码明明成功了）。
 *
 * 要进入业务应用，永远从应用页面发起：应用跳转授权端点带上自己的
 * client_id，平台这边检测到已有会话就直接发码，不再要密码。
 */
export default function WelcomePage() {
  const [me, setMe] = useState<UserInfo | null | undefined>(undefined)

  useEffect(() => {
    let alive = true
    authApi
      .me()
      .then((r) => alive && setMe(r))
      .catch(() => alive && setMe(null))
    return () => {
      alive = false
    }
  }, [])

  // 未登录：这个页面没有可展示的东西，回登录页
  if (me === null) return <Navigate to="/login" replace />

  if (me === undefined) {
    return (
      <div className="auth-shell">
        <div className="auth-card" style={{ textAlign: 'center' }}>
          <Loading />
        </div>
      </div>
    )
  }

  return (
    <div className="auth-shell">
      <div className="auth-card" style={{ textAlign: 'center' }}>
        <h1 style={{ fontSize: 19 }}>已登录统一登录平台</h1>
        <p style={{ marginTop: 8, fontSize: 14 }}>
          {me.nickname}
          <span className="muted" style={{ marginLeft: 6, fontSize: 13 }}>
            @{me.username}
          </span>
        </p>
        <p className="muted" style={{ fontSize: 13, marginTop: 12, lineHeight: 1.7 }}>
          这里是登录平台本身。要进入业务应用，请从应用页面发起登录 ——
          平台检测到本次会话后会直接完成授权，无需再次输入密码。
        </p>
        <div style={{ marginTop: 18, display: 'flex', gap: 10, justifyContent: 'center' }}>
          <a className="btn" href="/logout" style={{ textDecoration: 'none' }}>
            退出登录
          </a>
        </div>
      </div>
    </div>
  )
}
