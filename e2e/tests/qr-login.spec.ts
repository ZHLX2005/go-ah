import { test, expect, type BrowserContext, type Page } from '@playwright/test'

/**
 * 用例组 5：手机扫码登录（真实浏览器，双 context 模拟两台设备）
 *
 * 设计文档：docs/design/qr-login.md。这份用例验收的是**页面**，
 * 而不是接口 —— 接口层已经由 internal/logic/qr 的 11 个单测
 * 与 template-qr-client 的 7 项负向检查覆盖过，两者不能互相替代：
 *   · 只测接口，测不出"二维码真的画出来了"、"点 Tab 会切面板"、
 *     "手机端未登录时会不会被正确送回登录页再回来"；
 *   · 只测页面，测不出并发下票据只被领一次。
 *
 * ── 为什么必须用两个 context ──────────────────────────────────────────
 *
 * 扫码登录的全部安全模型就一句话：**PC 的 qr_ctx 与手机的 idp_session
 * 分属两台设备**。Playwright 的 context 之间 Cookie/storage 彻底隔离，
 * 正好是"两台设备"的忠实模型。如果图省事让两端共用一个 context，
 * 那么 qr_ctx 与 idp_session 会同源共存，转发攻击防线即使被删掉，
 * 这条用例依然全绿 —— 一个不会失败的测试在这里比没有测试更糟。
 *
 * ── 服务地址 ──────────────────────────────────────────────────────────
 *
 * 与 helpers.ts 里的 IDP 常量分开定义，是因为本用例只需要认证中心，
 * 不需要 8081 上的业务平台；同时支持 IDP_BASE 覆盖，便于换端口跑
 * （本机 8080 常被别的服务占住，用 18080 起认证中心是常态）。
 */
const IDP = process.env.IDP_BASE ?? 'http://127.0.0.1:8080'
const TEST_USER = { username: 'test', password: 'test123456' }
const SHOT = 'screenshots'

/** 口令方式登录（默认 Tab），并等页面离开 /login */
async function loginByPassword(page: Page, user = TEST_USER) {
  await page.waitForSelector('input[type=text]', { timeout: 15_000 })
  await page.fill('input[type=text]', user.username)
  await page.fill('input[type=password]', user.password)
  await page.click('button[type=submit]')
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 20_000 })
}

/**
 * PC 侧：打开登录页 → 切到扫码 Tab → 抓 POST /api/qr/sessions 的响应。
 *
 * 为什么用 waitForResponse 拿 qr_content，而不是从 DOM 里解二维码图片：
 * 那需要一个解码库，而"相机扫出来的就是这串 URL"这件事本来就是这个契约的定义 ——
 * 直接用接口返回的 qr_content，等价于真实扫码得到的内容，
 * 同时也顺带证明了前端确实调了这个端点才画出了图。
 */
async function openQrTabAndCaptureTicket(pc: Page): Promise<string> {
  await pc.goto(`${IDP}/login?return_to=${encodeURIComponent('/admin/users')}`, {
    waitUntil: 'domcontentloaded',
  })

  const created = pc.waitForResponse(
    (r) => r.url().includes('/api/qr/sessions') && r.request().method() === 'POST',
    { timeout: 20_000 },
  )

  await pc.getByRole('button', { name: '手机扫码' }).click()
  const body = await (await created).json()
  expect(body.code, `建票接口应当成功，实际 ${JSON.stringify(body)}`).toBe(0)

  // 这一条是"web 页面显示"的硬证据：面板里必须真出现一张位图二维码，
  // 而不是一句占位文字。src 前缀 data: 同时证明它是本地渲染的
  // —— 内容含 ticket，走任何在线出图服务都是凭据泄露（设计文档 §8）。
  const img = pc.locator('img[alt="登录二维码"]')
  await expect(img).toBeVisible({ timeout: 15_000 })
  // 取属性再断言字符串，而不是 toHaveAttribute(/src/, …)：后者把第一个参数
  // 当**属性名的正则**处理，在本版本下读回空串，于是"图片没渲染"与
  // "我的断言写错了"会报成同一个错 —— 一个只会误导人的失败。
  const src = (await img.getAttribute('src')) ?? ''
  expect(
    src,
    '二维码必须是本地渲染的 data: 图片（内容含 ticket，走任何在线出图服务都是凭据泄露）',
  ).toMatch(/^data:image\/(png|jpeg)/)

  await pc.screenshot({ path: `${SHOT}/qr-01-pc-login-qrcode.png` })
  return String(body.data.qr_content)
}

test.describe('手机扫码登录', () => {
  test('PC 出码 → 手机确认 → PC 领到会话，全程不输密码', async ({ browser }) => {
    test.setTimeout(120_000)

    // ── 设备 1：PC ──────────────────────────────────────────────────────
    const pcCtx: BrowserContext = await browser.newContext()
    const pc = await pcCtx.newPage()
    const qrContent = await openQrTabAndCaptureTicket(pc)
    expect(qrContent, '二维码内容必须是手机可打开的 https/http 链接').toMatch(/\/scan\?t=qrt_/)

    // ── 设备 2：手机（独立 context，因此独立 Cookie）────────────────────
    const phCtx: BrowserContext = await browser.newContext()
    const phone = await phCtx.newPage()

    // 手机端还没登录：页面应当把它送去登录页，并把 return_to 指回这一页
    await phone.goto(qrContent, { waitUntil: 'domcontentloaded' })
    await phone.waitForURL(/\/login\?return_to=/, { timeout: 20_000 })
    const backTo = new URL(phone.url()).searchParams.get('return_to') ?? ''
    expect(
      backTo.startsWith('/scan?t='),
      `登录成功后要回到扫码页，但 return_to 是 ${backTo}（丢了 ?t= 就等于回到一个空白确认页）`,
    ).toBe(true)

    await loginByPassword(phone)
    await phone.waitForURL(/\/scan\?t=/, { timeout: 20_000 })

    // 确认页必须把"要被登录的那台机器"讲清楚 —— 这是用户唯一的核对依据
    await phone.waitForSelector('text=/要登录的设备/')
    const deviceBox = phone.locator('.qr-device')
    await expect(deviceBox).toContainText(/Chrome/, { timeout: 10_000 })
    await expect(deviceBox).toContainText(/Windows|macOS|Linux/)
    await phone.screenshot({ path: `${SHOT}/qr-02-phone-confirm.png` })

    // ── 中间态：PC 应当看到"已扫码"，此时手机端还没点确认 ───────────────
    //
    // 这条断言是整套交互反馈的验收点：没有它，用户在手机上慢慢读设备信息时，
    // PC 那边只是一张静止的二维码，他会去重复扫码。
    //
    // 用精确文案而不是 /已扫码/ 正则：这个状态下遮罩层与下方说明**两处**都含
    // "已扫码"，正则会在 strict mode 下报"解析到 2 个元素" —— 也就是说
    // 功能是对的、断言写法会伪装成功能失败。
    await expect(pc.getByText('已扫码，请在手机上确认本次登录')).toBeVisible({ timeout: 15_000 })
    await pc.screenshot({ path: `${SHOT}/qr-03-pc-scanned-waiting.png` })

    // ── 批准 ────────────────────────────────────────────────────────────
    await phone.getByRole('button', { name: '确认登录' }).click()
    await phone.waitForSelector('text=/已确认登录/', { timeout: 20_000 })
    await phone.screenshot({ path: `${SHOT}/qr-04-phone-confirmed.png` })

    // ── PC 领取会话并自行跳到 return_to ────────────────────────────────
    //
    // 终点断言选 /admin/users 而不是"URL 变了"：管理台要求"已登录 + 是管理员"
    // 两个条件同时成立才会渲染表格。所以看到 test 这一行，
    // 就同时证明了 ① 会话 Cookie 真的下发到了 PC 浏览器、
    // ② 它是后端认账的全局会话、③ 它属于扫码批准时的那个账号（test 恰为管理员）。
    await pc.waitForURL((u) => u.pathname.startsWith('/admin'), { timeout: 25_000 })
    // .first() 不是随手加的：管理台用户表里 "test" 同时出现在账号、昵称、邮箱
    // 多个单元格里，而 Playwright 严格模式下**多匹配即报错**。本地种子数据恰好
    // 只命中一处所以能过，换一份数据（或 CI 里多几个 e2e 账号）就会红 ——
    // 这类"靠环境侥幸通过"的断言必须现在就收紧，而不是等 CI 教你。
    await expect(pc.locator('text=test').first()).toBeVisible({ timeout: 15_000 })
    await pc.screenshot({ path: `${SHOT}/qr-05-pc-logged-in-admin.png` })

    // 会话确实属于被批准的那个账号，而不是碰巧登录着的任何人
    const me = await pc.evaluate(async () => {
      const r = await fetch('/api/me', { credentials: 'include' })
      return await r.json()
    })
    expect(me.data?.username, 'PC 侧会话身份应与手机端批准的账号一致').toBe(TEST_USER.username)

    // ── 票据一次性：同一张码不能再用 ───────────────────────────────────
    await phone.goto(qrContent, { waitUntil: 'domcontentloaded' })
    await phone.waitForSelector('text=/已经完成|已失效|重新扫码|已经登录完成/', { timeout: 20_000 })

    await pcCtx.close()
    await phCtx.close()
  })

  test('手机端点「不是我操作」，PC 领不到会话', async ({ browser }) => {
    const pcCtx = await browser.newContext()
    const pc = await pcCtx.newPage()
    const qrContent = await openQrTabAndCaptureTicket(pc)

    const phCtx = await browser.newContext()
    const phone = await phCtx.newPage()
    await phone.goto(qrContent, { waitUntil: 'domcontentloaded' })
    await phone.waitForURL(/\/login\?return_to=/, { timeout: 20_000 })
    await loginByPassword(phone)
    await phone.waitForURL(/\/scan\?t=/, { timeout: 20_000 })
    await phone.waitForSelector('text=/要登录的设备/')

    await phone.getByRole('button', { name: '不是我操作' }).click()
    await phone.waitForSelector('text=/已拒绝该登录请求/', { timeout: 20_000 })

    // PC 侧必须停在"未登录"，且不能拿到会话
    await pc.waitForSelector('text=/二维码已作废|失效/', { timeout: 20_000 })
    const me = await pc.evaluate(async () => {
      const r = await fetch('/api/me', { credentials: 'include' })
      return await r.json()
    })
    expect(me.data ?? null, '被拒绝之后 PC 侧不应有任何登录态').toBeNull()

    await pcCtx.close()
    await phCtx.close()
  })

  test('把二维码链接给第三台设备：看不到进度，也领不走会话', async ({ browser }) => {
    // 这一测模拟"二维码被截图转发"：第三者拿到了完整 URL（图片里就有），
    // 但他既不是创建者（没有 qr_ctx），也没有批准权
    const pcCtx = await browser.newContext()
    const pc = await pcCtx.newPage()
    const qrContent = await openQrTabAndCaptureTicket(pc)

    const thiefCtx = await browser.newContext()
    const thief = await thiefCtx.newPage()
    // 必须先落到 IDP 源上再发 fetch：about:blank 的 origin 是 null，
    // 从那儿跨源请求会被 CORS 直接拒掉（Failed to fetch），
    // 于是"攻击被挡住"与"请求压根没发出去"报成同一个错。
    await thief.goto(`${IDP}/login`, { waitUntil: 'domcontentloaded' })

    // 从二维码内容里解出 ticket，并据此拼出轮询地址
    const ticket = new URL(qrContent).searchParams.get('t') ?? ''
    expect(ticket).toMatch(/^qrt_/)
    const pollUrl = new URL(`/api/qr/sessions/${encodeURIComponent(ticket)}`, IDP).href

    // 旁观者轮询同一张票：后端必须一律回 pending
    const seen = await thief.evaluate(async (url) => {
      const r = await fetch(url, { credentials: 'include' })
      return await r.json()
    }, pollUrl)
    expect(seen.data?.status, '无 qr_ctx 者不应看到真实进度').toBe('pending')

    // 他也不能替谁批准：未登录直接被挡
    const refused = await thief.evaluate(async (t) => {
      const r = await fetch(`/api/qr/sessions/${encodeURIComponent(t)}/confirm`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
      return { status: r.status, body: await r.json() }
    }, String(new URL(qrContent).searchParams.get('t')))
    expect(refused.status, '匿名调用 confirm 必须 401').toBe(401)
    expect(refused.body.error).toBe('unauthenticated')

    await pcCtx.close()
    await thiefCtx.close()
  })
})
