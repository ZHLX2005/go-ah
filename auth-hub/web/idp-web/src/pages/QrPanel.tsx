/**
 * 扫码登录面板（PC 侧）。
 *
 * 放在 pages/ 而不是 ui/：ui/ 是不碰网络与后端的原子层，而这个组件的全部职责
 * 就是"建票 → 画二维码 → 轮询 → 领取会话"这条网络链路。把它塞进 ui/ 会让
 * "原子层可以随便引"这个前提失效。
 *
 * ── 为什么用一条 async 循环而不是 setInterval ──────────────────────────────
 *
 * setInterval 不关心上一次请求有没有回来：网络一慢，几个 poll 就会并发在飞，
 * 而它们的响应到达顺序不等于发出顺序 —— 于是界面可能从 confirmed 倒回 pending，
 * 用户看到的是"登录成功了又变回二维码"。串行 await 天然保证同时只有一个请求。
 *
 * ── 关于领取（claim）的时机 ────────────────────────────────────────────────
 *
 * 轮询看到 confirmed 之后**另发一次** claim，而不是在轮询里顺手发 Cookie：
 * 手机端也要查状态，如果查询自带副作用，手机那一次查询会把会话建立到手机上，
 * PC 反而永远领不到。读写分开之后，只有这个组件会调 claim。
 *
 * claim 成功后不再轮询、直接回调让父级整页跳转 —— 继续轮询会对一张
 * 已 consumed 的票据反复拿 409，除了刷日志没有任何意义。
 */
import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { qrApi, ApiFailure, type QRStatus } from '@/api'
import { Alert, Button, Loading } from '@/ui'

/** 二维码内容渲染失败/未就绪时的占位尺寸，与真实图一致以免布局跳动 */
const QR_SIZE = 188

interface QrPanelProps {
  /** 领取成功（会话 Cookie 已由后端下发）。父级据此整页跳回 return_to */
  onClaimed: (username: string) => void
}

/** 连续失败多少次才放弃：一次网络抖动不该把用户刚看到的二维码换成错误框 */
const MAX_POLL_FAILURES = 3

export default function QrPanel({ onClaimed }: QrPanelProps) {
  // nonce 变化 = 重新生成一张二维码（"换一张"按钮、过期后重试）
  const [nonce, setNonce] = useState(0)
  const [phase, setPhase] = useState<'loading' | 'showing' | 'done'>('loading')
  const [qrUrl, setQrUrl] = useState('')
  const [status, setStatus] = useState<QRStatus>('pending')
  const [left, setLeft] = useState(0)
  const [err, setErr] = useState('')

  // 存活标记放 ref：effect 的清理函数与 async 循环都在闭包外读它，
  // 用 state 的话读到的是捕获时的旧值，卸载后仍会继续 setState。
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    let ticket = ''

    /** 轮询到 confirmed 后领取；返回 true 表示流程已终结 */
    async function finish(srvStatus: QRStatus): Promise<boolean> {
      if (srvStatus === 'confirmed') {
        setPhase('done')
        try {
          const r = await qrApi.claim(ticket)
          if (!alive.current) return true
          onClaimed(r.username)
        } catch (e) {
          // 票据在"查到 confirmed"与"发出 claim"之间过期/被清：
          // 这是正常竞态，退回等待态让用户刷新，而不是抛一个吓人的错误。
          if (!alive.current) return true
          setErr(
            e instanceof ApiFailure && e.reason === 'qr_expired'
              ? '二维码刚刚过期，请点击刷新后重试'
              : '领取登录态失败，请刷新二维码重试',
          )
          setPhase('showing')
          setStatus('expired')
        }
        return true
      }
      if (srvStatus === 'expired' || srvStatus === 'cancelled' || srvStatus === 'consumed') {
        setStatus(srvStatus)
        setErr(
          srvStatus === 'expired'
            ? '二维码已过期'
            : srvStatus === 'cancelled'
              ? '二维码已作废'
              : '这张二维码已经登录完成了',
        )
        return true
      }
      return false
    }

    async function run() {
      setPhase('loading')
      setErr('')
      setStatus('pending')
      setQrUrl('')

      let intervalMs = 1500
      try {
        const c = await qrApi.create()
        if (!alive.current) return
        ticket = c.ticket
        intervalMs = c.interval_ms > 0 ? c.interval_ms : 1500
        setLeft(c.expires_in)
        // 二维码在本地画：内容里含 ticket，交给任何在线出图服务都等于把凭据发出去，
        // 而且本项目此前已因依赖 CDN 出过离线故障 —— 这里必须自给自足。
        const url = await QRCode.toDataURL(c.qr_content, {
          width: QR_SIZE,
          margin: 1,
          errorCorrectionLevel: 'M',
        })
        if (!alive.current) return
        setQrUrl(url)
        setPhase('showing')
      } catch (e) {
        if (!alive.current) return
        setErr(describe(e))
        setPhase('showing')
        setStatus('expired')
        return
      }

      // 轮询途中的失败在**循环内**就地重试，而不是冒到外面：
      // 用户正拿手机对着屏幕扫，网络抖一下就把二维码换成错误框是纯粹的灾难。
      // 计数器也只能活在这一层 —— 放到外层 catch 里既读不到当前状态，
      // 也永远凑不齐"连续"这个语义。
      let failures = 0
      while (alive.current) {
        // 页签不可见时暂停轮询：合上笔记本盖半天再打开，
        // 不该为此攒下几百个注定失败的请求（票据其实早就过期了）。
        if (document.visibilityState === 'hidden') {
          await sleep(400)
          continue
        }
        try {
          const p = await qrApi.poll(ticket)
          if (!alive.current) return
          failures = 0
          setStatus(p.status)
          setLeft(p.expires_in)
          if (await finish(p.status)) return
        } catch (e) {
          if (!alive.current) return
          failures += 1
          if (failures >= MAX_POLL_FAILURES) {
            setErr(describe(e))
            return
          }
        }
        await sleep(intervalMs)
      }
    }

    void run()

    // 倒计时：与轮询解耦。轮询节奏是 1.5s，秒表要 1s 一跳才不显得卡顿，
    // 二者共用一个循环只会让倒计时跟着请求延迟一起漂。
    const tick = window.setInterval(() => setLeft((v) => (v > 0 ? v - 1 : 0)), 1000)

    return () => {
      alive.current = false
      window.clearInterval(tick)
      // 组件卸载或换码时作废旧票据：留着它，就等于留着一张
      // "屏幕上已经不显示、但依然能被人扫并批准"的二维码。
      if (ticket !== '') void qrApi.cancel(ticket).catch(() => undefined)
    }
    // 依赖只有 nonce：内部用到的其余状态（status/phase/qrUrl）都是本 effect
    // 自己写的派生值，加进依赖会让"每次状态跳一下就把票据换一张"。
    // onClaimed 同样不入依赖：它是父组件每次渲染新建的函数引用，
    // 收进来效果同上 —— 用户会看到二维码在不停地自己刷新。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce])

  if (phase === 'loading' && qrUrl === '') {
    return (
      <div style={{ padding: '28px 0', textAlign: 'center' }}>
        <Loading />
      </div>
    )
  }

  const blocked = status === 'scanned' ? false : err !== ''

  return (
    <div className="stack" style={{ gap: 12, alignItems: 'center' }}>
      <div
        className="qr-frame"
        style={{ opacity: status === 'scanned' || blocked ? 0.25 : 1 }}
      >
        {qrUrl !== '' && <img src={qrUrl} width={QR_SIZE} height={QR_SIZE} alt="登录二维码" />}
        {status === 'scanned' && <div className="qr-veil">已扫码<br />请在手机上确认</div>}
        {blocked && err !== '' && <div className="qr-veil">二维码失效</div>}
      </div>

      {blocked && err !== '' ? (
        <Alert kind="error">{err}</Alert>
      ) : status === 'scanned' ? (
        <p className="dim" style={{ fontSize: 13, margin: 0 }}>
          已扫码，请在手机上确认本次登录
        </p>
      ) : (
        <p className="dim" style={{ fontSize: 13, margin: 0 }}>
          使用已登录的手机 App 扫码 · <span className="mono">{left}s</span> 后失效
        </p>
      )}

      <Button block type="button" onClick={() => setNonce((n) => n + 1)}>
        {blocked ? '换一张二维码' : '刷新二维码'}
      </Button>

      <p className="dim" style={{ fontSize: 12, textAlign: 'center', margin: 0, lineHeight: 1.7 }}>
        二维码只用于登录认证中心，
        <br />
        不代表同意把账号信息交给任何第三方应用
      </p>
    </div>
  )
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

function describe(e: unknown): string {
  if (e instanceof ApiFailure) {
    if (e.status === 0) return '无法连接认证中心，请确认服务已启动'
    return e.message
  }
  return '二维码加载失败，请重试'
}
