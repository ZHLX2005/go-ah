/**
 * 手机扫码确认页 /scan?t=<ticket>
 *
 * 这是二维码内容指向的那个 https 地址在手机上的落点，承担设计文档 §9 里的
 * **兜底**角色：装了 App 时 Universal Link 直接把 ticket 交给 App 的原生确认页，
 * 没装 App（或深链失败）时才由浏览器打开这一页。两条路径打的是同一批后端接口，
 * 所以这里的逻辑就是 App 侧应当实现的逻辑的参照物。
 *
 * ── 这一页存在的唯一理由，是把"要被登录的那台机器"讲清楚 ──────────────
 *
 * 用户在这里点下的"确认登录"，效果等价于在另一台机器上输入了他的密码。
 * 他能核对这件事对不对，靠的只有中间那块设备画像（浏览器·系统 / IP / 来源 / 时间）。
 * 所以：
 *   - 画像缺失或取数失败时，**必须**拒绝出示确认按钮（宁可让他重扫，
 *     也不能让他对着一片空白点确认）；
 *   - 文案里不许出现"是否继续"这种不带对象的问句，必须点名是哪台机器。
 *
 * ── 为什么 scan 与 confirm 分两步发 ────────────────────────────────────
 *
 * 打开本页即发 scan，让 PC 端立刻从"等待扫码"变成"已扫码，请在手机确认"。
 * 如果只在点确认时发一次请求，用户在手机上慢慢读设备信息的这几秒里，
 * PC 那边始终是一张静止的二维码 —— 他无法区分"还没扫上"和"扫上了但卡住了"，
 * 于是会去重复扫码。中间态不是装饰，它是防重复操作的反馈。
 */
import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { qrApi, ApiFailure, type QRPreviewResult } from '@/api'
import { fmtTime } from '@/lib/format'
import { Alert, Button, Loading } from '@/ui'

export default function ScanPage() {
  const [sp] = useSearchParams()
  const ticket = sp.get('t') ?? ''

  const [data, setData] = useState<QRPreviewResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  /** done = 已把批准发给后端，等 PC 那边领走会话 */
  const [done, setDone] = useState<'confirmed' | 'refused' | ''>('')

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const p = await qrApi.preview(ticket)
      setData(p)
      // 取到预览即代表"这台手机确实扫到了这张码"，紧接着发 scan。
      // 失败不阻塞主流程：并发下可能已被另一台设备扫过，那不影响本机的确认能力
      // （pending|scanned → confirmed 两条路都合法），把二维码显示出来才是要紧事。
      if (p.status === 'pending') {
        void qrApi.scan(ticket).catch(() => undefined)
      }
    } catch (e) {
      if (e instanceof ApiFailure && e.status === 401) {
        // 未登录不是错误态，是一条正常的中转路径：去登录，登完回到这一页。
        // return_to 必须带上完整路径含 query —— 丢掉 ?t= 会让人登录后回到一个
        // 不知道要确认什么的空白页。
        redirectToLogin(ticket)
        return
      }
      setErr(describe(e))
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [ticket])

  useEffect(() => {
    if (ticket === '') {
      setErr('链接里没有二维码信息，请在电脑上重新扫码')
      setLoading(false)
      return
    }
    void load()
  }, [ticket, load])

  async function decide(action: 'confirm' | 'refuse') {
    if (ticket === '') return
    setBusy(true)
    setErr('')
    try {
      if (action === 'confirm') {
        await qrApi.confirm(ticket)
        setDone('confirmed')
      } else {
        await qrApi.refuse(ticket)
        setDone('refused')
      }
    } catch (e) {
      setErr(describe(e))
      // 状态失效这类问题靠重新取一次数最诚实：让页面显示后端此刻的真实状态，
      // 而不是留着一块已经过期、却仍然摆着"确认登录"按钮的界面。
      void load()
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <Shell>
        <Loading />
      </Shell>
    )
  }

  if (done === 'confirmed') {
    return (
      <Shell>
        <Alert kind="ok">已确认登录</Alert>
        <p className="dim" style={{ fontSize: 13, lineHeight: 1.8, margin: 0 }}>
          请在电脑上继续操作。这页可以关掉了。
        </p>
        <Button block type="button" onClick={() => setDone('')}>
          返回
        </Button>
      </Shell>
    )
  }

  if (done === 'refused') {
    return (
      <Shell>
        <Alert kind="info">已拒绝该登录请求</Alert>
        <p className="dim" style={{ fontSize: 13, lineHeight: 1.8, margin: 0 }}>
          电脑上那张二维码已经作废。如果那不是你本人的操作，
          说明有人把二维码发给了你 —— 建议顺手检查账号的登录记录。
        </p>
      </Shell>
    )
  }

  // 画像没拿到就不可能有确认按钮：见文件头那条硬约束
  if (err !== '' || data == null) {
    return (
      <Shell>
        <Alert kind="error">{err === '' ? '无法读取这次登录请求' : err}</Alert>
        <Button block type="button" onClick={() => void load()} disabled={busy}>
          重试
        </Button>
      </Shell>
    )
  }

  const terminal =
    data.status === 'consumed' ||
    data.status === 'cancelled' ||
    data.status === 'expired' ||
    data.status === 'confirmed'

  return (
    <Shell>
      <div>
        <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
          收到一个登录请求
        </div>
        <div style={{ fontSize: 17, fontWeight: 600 }}>有人要用你的账号登录</div>
      </div>

      <div className="qr-device">
        <div className="qr-device__label">要登录的设备</div>
        <div className="qr-device__value">{data.pc.ua || '未知设备'}</div>
        <div className="dim" style={{ fontSize: 12, marginTop: 6, lineHeight: 1.8 }}>
          来源 <span className="mono">{data.pc.geo || '未知'}</span>
          {' · '}
          <span className="mono">{data.pc.ip || '未知 IP'}</span>
          <br />
          发起于 <span className="mono">{fmtTime(data.pc.created_at)}</span>
        </div>
      </div>

      {terminal ? (
        <Alert kind="info">
          {data.status === 'confirmed'
            ? '这次登录已经批准过了，请等待电脑那边完成。'
            : data.status === 'consumed'
              ? '这次登录已经完成。'
              : '这张二维码已经失效，请在电脑上刷新后重新扫码。'}
        </Alert>
      ) : (
        <>
          <Alert kind="info">
            确认后就等于在<span style={{ fontWeight: 600 }}>上面那台机器</span>上登录你的账号。
            不是你自己发起的，请点「不是我操作」。
          </Alert>
          <div className="row" style={{ gap: 10 }}>
            <Button block type="button" onClick={() => void decide('refuse')} disabled={busy}>
              不是我操作
            </Button>
            <Button
              block
              type="button"
              variant="primary"
              onClick={() => void decide('confirm')}
              disabled={busy}
            >
              {busy ? '提交中…' : '确认登录'}
            </Button>
          </div>
        </>
      )}

      {err !== '' && <Alert kind="error">{err}</Alert>}
    </Shell>
  )
}

/** 统一的居中壳子，复用登录页那一套 auth-shell / auth-card */
function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth-shell">
      <div className="auth-card stack" style={{ gap: 16 }}>
        {children}
      </div>
      <p className="auth-foot">统一登录平台 · 扫码登录确认</p>
    </div>
  )
}

/**
 * 未登录时跳去登录页，并让登录成功后回到本页。
 *
 * 用 location.assign 而不是 react-router 的 navigate：目标 /login 虽然也在
 * 这个 SPA 里，但"登录后端要整页刷一次才能拿到会话"这条约束（见 Login.tsx）
 * 意味着这里没有任何理由留在当前文档里 —— 少一种跳转方式就少一类差异。
 */
function redirectToLogin(ticket: string) {
  const back = `/scan?t=${encodeURIComponent(ticket)}`
  window.location.assign(`/login?return_to=${encodeURIComponent(back)}`)
}

function describe(e: unknown): string {
  if (e instanceof ApiFailure) {
    if (e.status === 0) return '无法连接认证中心，请检查网络'
    if (e.status === 404) return '二维码无效或已失效，请在电脑上刷新后重新扫码'
    if (e.status === 409) return '这张二维码的状态已经变了，请重新扫码'
    if (e.status === 410) return '二维码已过期，请在电脑上刷新后重新扫码'
    return e.message
  }
  return '操作失败，请重试'
}
