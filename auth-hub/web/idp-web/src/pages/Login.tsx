import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { authApi, ApiFailure } from '@/api'
import { Alert, Button, Field, Input } from '@/ui'

/**
 * 登录页 /login
 *
 * 这是 OIDC 授权码流程里用户唯一输入凭据的地方：/oauth2/auth 发现未登录时
 * 302 到这里，并带上 return_to 指向原来的授权请求。
 * 登录成功后按后端返回的 return_to 整页跳回去，继续授权流程 ——
 * **不能用前端路由跳**，因为 return_to 是 /oauth2/auth 这个服务端端点，
 * 它要靠浏览器发起真实请求才会走 302 → 授权确认页。
 */
export default function LoginPage() {
  const [sp] = useSearchParams()
  const returnTo = sp.get('return_to') ?? '/oauth2/auth'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr('')

    // 前端先挡一道：空提交没必要打后端
    if (!username.trim()) {
      setErr('请输入账号或邮箱')
      return
    }
    if (!password) {
      setErr('请输入密码')
      return
    }

    setBusy(true)
    try {
      const res = await authApi.login(username.trim(), password, returnTo)
      // 后端把「登录成功 + 该回哪里」一并算好返回，前端不自己拼
      window.location.href = res.return_to
    } catch (e2) {
      setErr(loginErrorText(e2))
      setBusy(false)
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="row" style={{ gap: 12 }}>
          <span className="auth-mark">ID</span>
          <div>
            <div style={{ fontWeight: 600, letterSpacing: 0.5 }}>统一登录平台</div>
            <div className="dim" style={{ fontSize: 12 }}>
              Identity Provider · OIDC PKCE
            </div>
          </div>
        </div>

        <div className="auth-divider" />

        <form onSubmit={onSubmit} className="stack" style={{ gap: 14 }}>
          <Field label="账号或邮箱">
            <Input
              size="lg"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="账号或邮箱"
              autoComplete="username"
              autoFocus
            />
          </Field>

          <Field label="密码">
            <Input
              size="lg"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="请输入密码"
              autoComplete="current-password"
            />
          </Field>

          {err !== '' && <Alert kind="error">{err}</Alert>}

          <Button variant="primary" size="lg" block type="submit" disabled={busy}>
            {busy ? '登录中…' : '登 录'}
          </Button>
        </form>

        {/* 这里曾经有一个「一键填充 test / test123456」的按钮。
            它在演示环境里很省事，但只要有一次带真实口令的部署被构建，
            口令就作为字面量进了公开可下载的 JS 产物（以及浏览器缓存、
            CDN 日志）。管理员的取值本来就由 IDP_ADMIN_* 配置决定，
            前端无从得知也不该知道，所以整块删掉而不是改成读环境变量。 */}

        <div className="auth-divider" />

        {/* 带上 return_to：注册成功后要接着走同一条授权流程 */}
        <p className="dim" style={{ fontSize: 12, textAlign: 'center', margin: 0 }}>
          没有账号？{' '}
          <Link
            to={`/register?return_to=${encodeURIComponent(returnTo)}`}
            style={{ color: 'inherit', textDecoration: 'underline' }}
          >
            用邀请码注册
          </Link>
        </p>
      </div>

      <p className="auth-foot">登录成功后将继续完成 OIDC 授权流程</p>
    </div>
  )
}

/**
 * 把后端的 error 码翻译成用户能据此行动的话。
 * 「账号不存在」和「密码错误」必须分开 —— 合成一句「用户名或密码错误」
 * 虽然更安全，但在内网自建认证中心里只会让人反复试密码。
 */
function loginErrorText(e: unknown): string {
  if (e instanceof ApiFailure) {
    if (e.reason === 'user_not_found') return '账号或邮箱不存在'
    if (e.reason === 'wrong_password') return '密码错误'
    if (e.status === 0) return '无法连接认证中心，请确认服务已启动'
    return e.message
  }
  return '登录失败，请重试'
}
