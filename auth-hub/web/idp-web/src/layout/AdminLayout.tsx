import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { adminApi, ApiFailure } from '@/api'
import type { AdminUser } from '@/api/types'
import { Alert, Button, Loading } from '@/ui'

type Gate = 'loading' | 'ok' | 'unauth' | 'forbidden'

/**
 * 管理台外壳。
 *
 * 三重门控，顺序不能颠倒：
 *   ① 401 → 未登录。跳登录页并带 return_to 回到当前页
 *      （用 window.location 而不是 navigate：登录是整页跳转的服务端流程，
 *        且要让浏览器带上原样的 query，react-router 的 state 在这条链路上会丢）
 *   ② 403 → 已登录但不是管理员。**必须停在原地给出说明**，
 *      不能再跳登录页 —— 用户明明登录了却被要求登录，会以为系统坏了
 *   ③ 通过 → 渲染侧栏与面板
 */
export default function AdminLayout() {
  const [gate, setGate] = useState<Gate>('loading')
  const [admin, setAdmin] = useState<AdminUser | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const me = await adminApi.me()
        if (cancelled) return
        setAdmin(me)
        setGate(me?.is_admin ? 'ok' : 'forbidden')
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiFailure && e.status === 401) {
          setGate('unauth')
          const back = encodeURIComponent(window.location.pathname + window.location.search)
          window.location.href = `/login?return_to=${back}`
          return
        }
        // 403 与其他错误都按「无权限」处理，并保留原因便于排查
        setGate('forbidden')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  if (gate === 'loading') return <Loading text="正在校验管理员权限…" />

  if (gate === 'unauth') {
    return <Loading text="未登录，正在跳转登录页…" />
  }

  if (gate === 'forbidden') {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <h1 style={{ fontSize: 18, marginBottom: 8 }}>无权访问管理台</h1>
          <Alert kind="error">
            当前账号不是管理员。管理台需要 <code>users.is_admin = true</code>，
            后端在 <code>/api/admin/*</code> 上统一拦截。
          </Alert>
          <div className="row" style={{ marginTop: 20 }}>
            <Button onClick={() => (window.location.href = '/login')}>切换账号</Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand__mark">ID</span>
          <span>统一登录平台</span>
        </div>
        <nav className="nav">
          <div className="nav__group">管理台</div>
          <NavItem to="/admin/users">用户</NavItem>
          <NavItem to="/admin/invites">邀请码</NavItem>
          <NavItem to="/admin/clients">OIDC 客户端</NavItem>
          <NavItem to="/admin/tokens">令牌</NavItem>
          <div className="nav__group">认证页面</div>
          <NavItem to="/login">登录页</NavItem>
          <NavItem to="/register">注册页</NavItem>
        </nav>
      </aside>

      <div className="main">
        <header className="topbar">
          <span className="dim" style={{ fontSize: 12 }}>
            管理员
          </span>
          <span className="grow" />
          <span className="dim" style={{ fontSize: 12 }}>
            {admin?.username} · {admin?.email}
          </span>
          <Button
            size="sm"
            onClick={() => {
              // 走 IdP 的 RP-Initiated Logout 确认页，登出后回到登录页
              const pl = encodeURIComponent(`${window.location.origin}/login`)
              window.location.href = `/logout?post_logout_redirect_uri=${pl}`
            }}
          >
            登出
          </Button>
        </header>
        <div className="page">
          <Outlet />
        </div>
      </div>
    </div>
  )
}

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  return (
    <NavLink to={to} className={({ isActive }) => (isActive ? 'nav__item nav__item--active' : 'nav__item')}>
      {children}
    </NavLink>
  )
}

/** 面板标题栏：三个面板统一用它起头 */
export function PanelHeader({
  title,
  desc,
  extra,
}: {
  title: ReactNode
  desc?: ReactNode
  extra?: ReactNode
}) {
  return (
    <div className="row-between" style={{ marginBottom: 16 }}>
      <div>
        <div className="page-title">{title}</div>
        {desc != null && <p className="page-desc">{desc}</p>}
      </div>
      {extra != null && <div className="row">{extra}</div>}
    </div>
  )
}
