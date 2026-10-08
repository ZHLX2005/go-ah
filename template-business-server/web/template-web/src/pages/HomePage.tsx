import { useEffect, useRef, useState } from 'react'
import { fetchSession, fetchProfile, logout, refreshToken } from '../api'
import { startLogin } from '../oidc'
import type { Profile } from '../types'

/**
 * 业务首页 /
 * - 未登录：提示并自动触发 PKCE 授权跳转（跳转 IDP 授权地址）
 * - 已登录：展示 sub / profile 信息，提供【刷新用户信息】【统一登出】
 */
export default function HomePage() {
  const [profile, setProfile] = useState<Profile | null>(null)
  const [checking, setChecking] = useState(true)
  const [redirecting, setRedirecting] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const autoStarted = useRef(false)

  // 首次加载：探测登录态，未登录则自动发起 PKCE 授权
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const s = await fetchSession()
        if (cancelled) return
        if (!s.data) {
          if (!autoStarted.current) {
            autoStarted.current = true
            setRedirecting(true)
            // 自动触发 PKCE 授权跳转
            await startLogin()
          }
          return
        }
        const p = await fetchProfile()
        if (cancelled) return
        if (p.data) setProfile(p.data)
        else setError(p.error ?? '获取用户信息失败')
      } catch (e) {
        if (!cancelled) setError('无法连接业务后端，请确认服务已启动')
        console.error(e)
      } finally {
        if (!cancelled) setChecking(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  /** 刷新用户信息：重新拉取受保护接口 */
  async function onRefresh() {
    setBusy(true)
    setNotice('')
    setError('')
    try {
      const p = await fetchProfile()
      if (p.data) {
        setProfile(p.data)
        setNotice('用户信息已刷新（' + new Date().toLocaleTimeString() + '）')
      } else {
        setError('会话已失效：' + (p.error ?? 'unauthorized'))
      }
    } finally {
      setBusy(false)
    }
  }

  /** 刷新 token（演示 refresh_token 链路） */
  async function onRefreshToken() {
    setBusy(true)
    setNotice('')
    setError('')
    try {
      const r = await refreshToken()
      if (r.code === 0) setNotice('token 刷新成功：已通过 refresh_token 获取新的 id_token')
      else setError('token 刷新失败：' + (r.message ?? r.error ?? 'unknown'))
    } finally {
      setBusy(false)
    }
  }

  /** 统一登出：先清业务会话，再跳 IDP 完成单点登出 */
  async function onLogout() {
    setBusy(true)
    try {
      const r = await logout()
      if (r.logout_url) {
        window.location.href = r.logout_url
      } else {
        window.location.reload()
      }
    } catch {
      setBusy(false)
      setError('登出失败')
    }
  }

  // ---------- 渲染 ----------
  if (checking || redirecting) {
    return (
      <Centered>
        <Spinner />
        <h1 className="text-lg font-semibold text-slate-700 mt-4">
          {redirecting ? '检测到未登录，正在跳转统一登录平台…' : '正在检查登录状态…'}
        </h1>
        <p className="text-sm text-slate-400 mt-2">
          即将携带 state / code_challenge(S256) 跳转到 IDP 授权端点
        </p>
      </Centered>
    )
  }

  return (
    <div className="min-h-screen bg-slate-100">
      {/* 顶部导航 */}
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600 flex items-center justify-center text-white font-bold">
              T
            </div>
            <div>
              <div className="font-semibold text-slate-800">模板业务平台</div>
              <div className="text-xs text-slate-400">OIDC PKCE 接入参考 Demo</div>
            </div>
          </div>
          {profile && <Badge text="已登录" color="emerald" />}
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-6">
        {error && (
          <Alert color="red" title="出错了">
            {error}
          </Alert>
        )}
        {notice && <Alert color="emerald" title="操作成功">{notice}</Alert>}

        {!profile && (
          <div className="bg-white rounded-2xl shadow-sm p-10 text-center">
            <div className="text-4xl mb-3">🔓</div>
            <h2 className="text-lg font-semibold text-slate-700">尚未登录</h2>
            <p className="text-sm text-slate-500 mt-2">
              本页会自动发起 OIDC PKCE 授权跳转，若未跳转请点击下方按钮
            </p>
            <button
              onClick={() => startLogin()}
              className="mt-5 bg-indigo-600 hover:bg-indigo-700 text-white font-medium px-6 py-2.5 rounded-lg transition"
            >
              前往统一登录
            </button>
          </div>
        )}

        {profile && (
          <>
            {/* 用户信息卡片 */}
            <section className="bg-white rounded-2xl shadow-sm overflow-hidden">
              <div className="bg-gradient-to-r from-indigo-500 to-indigo-600 px-6 py-5 text-white">
                <div className="text-xs opacity-80">当前登录用户（来自 IDP id_token）</div>
                <div className="text-xl font-semibold mt-1">{profile.nickname || profile.username}</div>
                <div className="text-xs opacity-80 mt-1 font-mono">sub: {profile.sub}</div>
              </div>
              <dl className="divide-y divide-slate-100">
                <Row label="sub（唯一标识）" value={profile.sub} mono />
                <Row label="username" value={profile.username} />
                <Row label="nickname" value={profile.nickname} />
                <Row label="email" value={profile.email} />
                <Row label="最近登录" value={new Date(profile.last_login_at).toLocaleString()} />
                <Row label="会话过期" value={new Date(profile.session_expires_at).toLocaleString()} />
              </dl>
            </section>

            {/* 令牌保管情况（方案1：token 在后端） */}
            <section className="bg-white rounded-2xl shadow-sm p-6">
              <h3 className="font-semibold text-slate-800 mb-3 text-sm">令牌保管状态（业务后端）</h3>
              <div className="flex flex-wrap gap-3">
                <Badge text={profile.has_id_token ? 'id_token 已保管' : 'id_token 缺失'} color={profile.has_id_token ? 'indigo' : 'slate'} />
                <Badge text={profile.has_refresh_token ? 'refresh_token 已保管' : '无 refresh_token'} color={profile.has_refresh_token ? 'indigo' : 'slate'} />
                <Badge text="浏览器不接触 token" color="emerald" />
              </div>
              <p className="text-xs text-slate-400 mt-3">
                方案1：code + code_verifier 提交至业务后端完成换 token，token 仅存于服务端 SQLite，
                前端只持有 HttpOnly 会话 Cookie。
              </p>
            </section>

            {/* 操作区 */}
            <section className="bg-white rounded-2xl shadow-sm p-6">
              <h3 className="font-semibold text-slate-800 mb-4 text-sm">操作</h3>
              <div className="flex flex-wrap gap-3">
                <button
                  disabled={busy}
                  onClick={onRefresh}
                  className="bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white text-sm font-medium px-5 py-2.5 rounded-lg transition"
                >
                  刷新用户信息
                </button>
                <button
                  disabled={busy}
                  onClick={onRefreshToken}
                  className="border border-slate-300 text-slate-700 hover:bg-slate-50 disabled:opacity-50 text-sm font-medium px-5 py-2.5 rounded-lg transition"
                >
                  刷新 Token
                </button>
                <button
                  disabled={busy}
                  onClick={onLogout}
                  className="bg-rose-600 hover:bg-rose-700 disabled:bg-rose-400 text-white text-sm font-medium px-5 py-2.5 rounded-lg transition"
                >
                  统一登出
                </button>
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  )
}

/* ---------- 简易 UI 组件 ---------- */

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-slate-100 px-4 text-center">
      {children}
    </div>
  )
}

function Spinner() {
  return (
    <div className="w-10 h-10 border-4 border-indigo-200 border-t-indigo-600 rounded-full animate-spin" />
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex px-6 py-3 text-sm">
      <dt className="w-40 shrink-0 text-slate-500">{label}</dt>
      <dd className={`text-slate-800 break-all ${mono ? 'font-mono text-xs' : ''}`}>{value || '-'}</dd>
    </div>
  )
}

function Badge({ text, color }: { text: string; color: 'emerald' | 'indigo' | 'slate' }) {
  const map = {
    emerald: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    slate: 'bg-slate-100 text-slate-500 border-slate-200',
  }
  return <span className={`text-xs px-3 py-1 rounded-full border ${map[color]}`}>{text}</span>
}

function Alert({ color, title, children }: { color: 'red' | 'emerald'; title: string; children: React.ReactNode }) {
  const map = {
    red: 'bg-red-50 border-red-200 text-red-700',
    emerald: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  }
  return (
    <div className={`border rounded-xl px-5 py-4 text-sm ${map[color]}`}>
      <div className="font-semibold mb-0.5">{title}</div>
      <div>{children}</div>
    </div>
  )
}
