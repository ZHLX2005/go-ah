import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { authApi, adminApi } from '@/api'
import type { UserInfo } from '@/api'
import { Loading } from '@/ui'

/**
 * 统一登录平台首页 /
 *
 * 扫码/口令登录建立的是**平台自己的会话**（idp_session），与任何接入方无关。
 * 无业务方上下文时（直接打开平台、扫码成功），登录成功自动落在这里；
 * 有业务方上下文时 return_to 带着完整授权参数，不会经过本页。
 *
 * 曾经登录后的兜底落点是裸 /oauth2/auth —— 授权端点天生要求 client_id，
 * "扫码明明成功了"却看到 invalid client_id，就是这个错位。
 *
 * 要进入业务应用，永远从应用页面发起：应用跳授权端点带上 client_id，
 * 平台检测到本次会话后直接发码，不再要密码。
 */
export default function HomePage() {
  const [me, setMe] = useState<UserInfo | null | undefined>(undefined)
  const [isAdmin, setIsAdmin] = useState(false)

  useEffect(() => {
    let alive = true
    authApi
      .me()
      .then((r) => {
        if (!alive) return
        setMe(r)
        if (r == null) return
        // 管理员身份用管理端点探测：非管理员收到 401/403，静默收起入口即可，
        // 不值得为此把 is_admin 塞进面向所有用户的 /api/me 响应里。
        adminApi
          .me()
          .then(() => alive && setIsAdmin(true))
          .catch(() => alive && setIsAdmin(false))
      })
      .catch(() => alive && setMe(null))
    return () => {
      alive = false
    }
  }, [])

  // 未登录：首页没有可展示的东西，去登录页
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
        <h1 style={{ fontSize: 19 }}>统一登录平台</h1>
        <p style={{ marginTop: 8, fontSize: 14 }}>
          {me.nickname}
          <span className="muted" style={{ marginLeft: 6, fontSize: 13 }}>
            @{me.username}
          </span>
        </p>
        <p className="muted" style={{ fontSize: 13, marginTop: 4 }}>已登录</p>
        <p className="muted" style={{ fontSize: 13, marginTop: 12, lineHeight: 1.7 }}>
          要进入业务应用，请从应用页面发起登录 —— 平台检测到本次会话后
          会直接完成授权，无需再次输入密码。
        </p>
        <div style={{ marginTop: 18, display: 'flex', gap: 10, justifyContent: 'center' }}>
          {isAdmin && (
            <a className="btn" href="/admin/users" style={{ textDecoration: 'none' }}>
              管理后台
            </a>
          )}
          <a className="btn" href="/logout" style={{ textDecoration: 'none' }}>
            退出登录
          </a>
        </div>
      </div>
    </div>
  )
}
