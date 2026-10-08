import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { fetchAdminMe, type AdminUser } from '../adminApi'

/**
 * Admin 布局
 * - 进入 /admin 前校验全局 session + is_admin
 * - 未登录(401) -> 跳转登录页并带 return_to 回到当前页
 * - 非管理员(403) -> 展示无权限提示
 * - 侧边导航栏：IDP 页面（登录页/授权确认页）+ Admin 三个面板
 */
export default function AdminLayout() {
  const [state, setState] = useState<'loading' | 'ok' | 'forbidden' | 'unauth'>('loading')
  const [admin, setAdmin] = useState<AdminUser | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const res = await fetchAdminMe()
        if (cancelled) return
        if (res.__status === 401 || !res.data) {
          setState('unauth')
          // 跳转登录页，登录后回到管理后台
          const back = encodeURIComponent(window.location.pathname + window.location.search)
          window.location.href = `/login?return_to=${back}`
          return
        }
        if (!res.data.is_admin) {
          setState('forbidden')
          return
        }
        setAdmin(res.data)
        setState('ok')
      } catch {
        if (!cancelled) setState('forbidden')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [navigate])

  if (state === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100">
        <div className="text-center">
          <div className="w-10 h-10 mx-auto border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin" />
          <p className="text-sm text-slate-500 mt-4">正在校验管理员权限…</p>
        </div>
      </div>
    )
  }

  if (state === 'unauth') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100">
        <p className="text-sm text-slate-500">未登录，正在跳转登录页…</p>
      </div>
    )
  }

  if (state === 'forbidden') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100 px-4">
        <div className="bg-white rounded-2xl shadow-xl p-10 max-w-md text-center">
          <div className="text-5xl mb-4">🚫</div>
          <h1 className="text-xl font-bold text-slate-800">403 无访问权限</h1>
          <p className="text-sm text-slate-500 mt-2">
            当前账号不是管理员，无法访问管理后台。
            <br />
            预置管理员账号为 <span className="font-mono">test</span>。
          </p>
          <button
            onClick={() => navigate('/login')}
            className="mt-6 bg-indigo-600 hover:bg-indigo-700 text-white font-medium px-6 py-2.5 rounded-lg transition"
          >
            重新登录
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-100 flex">
      {/* 侧边导航栏 */}
      <aside className="w-60 shrink-0 bg-slate-900 text-slate-300 flex flex-col">
        <div className="px-5 py-5 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white text-sm font-bold">
              ID
            </div>
            <div>
              <div className="text-sm font-semibold text-white">统一登录平台</div>
              <div className="text-[11px] text-slate-500">管理后台</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <NavGroup title="IDP 页面" />
          <SideLink to="/login" label="登录页" icon="🔑" />
          <SideLink to="/consent" label="授权确认页" icon="🔐" />
          <SideLink to="/logout" label="登出确认页" icon="⏏" />

          <NavGroup title="管理后台" />
          <SideLink to="/admin/users" label="用户管理" icon="👥" />
          <SideLink to="/admin/clients" label="OIDC 客户端" icon="🧩" />
          <SideLink to="/admin/tokens" label="Token 管理" icon="🎫" />
        </nav>

        <div className="px-5 py-4 border-t border-slate-800">
          <div className="text-[11px] text-slate-500 mb-1">当前管理员</div>
          <div className="text-sm text-white font-medium truncate">
            {admin?.nickname || admin?.username}
          </div>
          <a
            href="/oauth2/logout?post_logout_redirect_uri=/login"
            className="mt-3 block text-center text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg py-2 transition"
          >
            退出登录
          </a>
        </div>
      </aside>

      {/* 主内容区 */}
      <main className="flex-1 min-w-0">
        <Outlet />
      </main>
    </div>
  )
}

function NavGroup({ title }: { title: string }) {
  return (
    <div className="px-3 pt-4 pb-1.5 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
      {title}
    </div>
  )
}

function SideLink({ to, label, icon }: { to: string; label: string; icon: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition ${
          isActive ? 'bg-indigo-600 text-white' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
        }`
      }
    >
      <span className="text-base">{icon}</span>
      <span>{label}</span>
    </NavLink>
  )
}

/** 页面通用头部 */
export function PageHeader({ title, desc, action }: { title: string; desc?: string; action?: ReactNode }) {
  return (
    <div className="bg-white border-b border-slate-200 px-8 py-5 flex items-center justify-between">
      <div>
        <h1 className="text-lg font-bold text-slate-800">{title}</h1>
        {desc && <p className="text-sm text-slate-500 mt-0.5">{desc}</p>}
      </div>
      {action}
    </div>
  )
}
