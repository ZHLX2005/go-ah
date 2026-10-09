import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { authApi, ApiFailure } from '@/api'
import { Alert, Button, Field, Input } from '@/ui'

/**
 * 注册页 /register
 *
 * 本平台**没有开放的注册入口**：注册必须携带一张"此刻仍能核销"的邀请码，
 * 而邀请码只由管理员生成（见 /admin/invites）。所以这张表单的第一件事不是
 * 收账号密码，而是把邀请码收下 —— 没有码，后面填得再对也不会建档。
 *
 * 注册成功即登录（后端直接下发会话 Cookie 并按 return_to 回到原授权请求），
 * 与登录页共用同一条后续链路：让用户注册完再打一遍刚刚设好的口令，是纯粹的
 * 刁难，而且没有任何安全收益。
 */
export default function RegisterPage() {
  const [sp] = useSearchParams()
  const returnTo = sp.get('return_to') ?? '/oauth2/auth'

  const [inviteCode, setInviteCode] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr('')

    // 本地先挡一道：这些错误后端也会拦，但没必要为一次注定失败的请求
    // 走一个来回（而且注册会用掉邀请码次数吗？不会 —— 后端把输入校验
    // 全放在核销之前，见 controller/auth.Register 的顺序说明）。
    const code = inviteCode.trim()
    const name = username.trim()
    const mail = email.trim()
    if (!code) {
      setErr('请填写邀请码')
      return
    }
    if (!name) {
      setErr('请输入账号')
      return
    }
    if (name.length < 3 || name.length > 32) {
      setErr('账号长度需在 3-32 个字符之间')
      return
    }
    if (!/^[A-Za-z0-9_.-]+$/.test(name)) {
      setErr('账号只能包含字母、数字、下划线、点和横线')
      return
    }
    if (!mail) {
      setErr('请输入邮箱')
      return
    }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) {
      setErr('邮箱格式不正确')
      return
    }
    // 长度下限与后端 consts.MinPasswordLength 一致。前端这份只为了少一次
    // 往返，判据仍以后端为准 —— 所以两处不一致时是"前端放开、后端拒绝"，
    // 而不是反过来（后者会让用户以为自己设的密码能过）。
    if (password.length < 8) {
      setErr('密码至少需要 8 个字符')
      return
    }
    if (password !== confirm) {
      setErr('两次输入的密码不一致')
      return
    }

    setBusy(true)
    try {
      const res = await authApi.register({
        username: name,
        password,
        email: mail,
        invite_code: code,
        return_to: returnTo,
      })
      // 与登录一致：整页跳到后端算好的地址，继续 OIDC 授权流程
      window.location.href = res.return_to
    } catch (e2) {
      setErr(registerErrorText(e2))
      setBusy(false)
    }
  }

  const loginHref = `/login?return_to=${encodeURIComponent(returnTo)}`

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="row" style={{ gap: 12 }}>
          <span className="auth-mark">ID</span>
          <div>
            <div style={{ fontWeight: 600, letterSpacing: 0.5 }}>注册账号</div>
            <div className="dim" style={{ fontSize: 12 }}>
              需要管理员发放的邀请码
            </div>
          </div>
        </div>

        <div className="auth-divider" />

        <form onSubmit={onSubmit} className="stack" style={{ gap: 14 }}>
          <Field label="邀请码" hint="由管理员生成，区分大小写">
            <Input
              size="lg"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder="inv_xxxxxxxxxxxxx"
              autoComplete="off"
              autoFocus
            />
          </Field>

          <Field label="账号" hint="3-32 个字符，可用字母、数字、下划线、点、横线">
            <Input
              size="lg"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="登录时使用的账号"
              autoComplete="username"
            />
          </Field>

          <Field label="邮箱">
            <Input
              size="lg"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
            />
          </Field>

          <Field label="密码" hint="至少 8 个字符">
            <Input
              size="lg"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="设置登录密码"
              autoComplete="new-password"
            />
          </Field>

          <Field label="确认密码">
            <Input
              size="lg"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="再输入一次"
              autoComplete="new-password"
            />
          </Field>

          {err !== '' && <Alert kind="error">{err}</Alert>}

          <Button variant="primary" size="lg" block type="submit" disabled={busy}>
            {busy ? '注册中…' : '注 册'}
          </Button>
        </form>

        <div className="auth-divider" />

        <p className="dim" style={{ fontSize: 12, textAlign: 'center', margin: 0 }}>
          已有账号？{' '}
          <Link to={loginHref} style={{ color: 'inherit', textDecoration: 'underline' }}>
            返回登录
          </Link>
        </p>
      </div>

      <p className="auth-foot">注册成功后将直接登录，并继续完成 OIDC 授权流程</p>
    </div>
  )
}

/**
 * 把后端的失败原因翻成用户能据此行动的话。
 *
 * 必须区分「码的问题」和「账号的问题」：前者要找管理员换码，后者自己改一个
 * 就能过。合成一句「注册失败」的话，用户唯一能做的就是把整页重填一遍 ——
 * 而重填一遍仍然是同样的结果。
 */
function registerErrorText(e: unknown): string {
  if (e instanceof ApiFailure) {
    switch (e.reason) {
      // 邀请码类：后端 message 已说明是哪种不可用，这里补上"该怎么办"
      case 'invite_not_found':
        return e.message || '邀请码不存在，请核对后重试'
      case 'invite_disabled':
        return '该邀请码已被停用，请联系管理员'
      case 'invite_expired':
        return '该邀请码已过期，请联系管理员重新生成'
      case 'invite_exhausted':
        return '该邀请码的可用次数已用完，请联系管理员重新生成'
      case 'username_taken':
        return '该账号已被占用，请换一个'
      // 输入类：文案里的数字来自后端常量，直接透出以保持单一来源
      case 'invalid_username':
      case 'invalid_password':
      case 'invalid_email':
        return e.message
      case 'invalid_request':
        return e.message || '请求参数有误'
    }
    if (e.status === 0) return '无法连接认证中心，请确认服务已启动'
    return e.message
  }
  return '注册失败，请重试'
}
