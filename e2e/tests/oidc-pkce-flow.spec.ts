import { test, expect } from '@playwright/test'
import {
  BIZ,
  IDP,
  TEST_USER,
  loginWithPKCE,
  fetchBizProfile,
  assertServicesUp,
} from './helpers'

/**
 * 用例组 1：OIDC 1.0 PKCE 授权码模式端到端流程
 *
 * 覆盖：
 *  1. 未登录访问业务首页自动跳转 IDP（携带 PKCE 参数）
 *  2. 错误密码被拒绝
 *  3. 账号栏填邮箱同样能登录
 *  4. 正确登录 -> 授权确认页 -> 回调换 token -> 建立业务会话
 *  5. 受保护接口鉴权通过
 *  6. 统一登出后业务接口 401、IDP 重新要求登录
 */
test.describe('OIDC PKCE 授权码流程', () => {
  test.beforeEach(async ({ page }) => {
    await assertServicesUp(page)
  })

  test('未登录访问业务首页，自动跳转 IDP 并携带完整 PKCE 参数', async ({ page }) => {
    await page.goto(BIZ + '/', { waitUntil: 'domcontentloaded' })

    // 跳到 IDP 后有两种落地形式：
    //   a) 未登录 -> /login?return_to=<原始授权 URL>（IDP 先要求登录）
    //   b) 已登录 -> 直接停在 /oauth2/auth
    await page.waitForURL(/127\.0\.0\.1:8080\/(login|oauth2\/auth)/, { timeout: 20_000 })
    const ref = page.url()

    // 统一还原出"原始授权请求 URL"
    let authURL: URL
    if (ref.includes('/login')) {
      const returnTo = new URL(ref).searchParams.get('return_to')
      expect(returnTo, 'IDP 登录页应通过 return_to 携带原始授权请求').toBeTruthy()
      authURL = new URL(returnTo!, 'http://127.0.0.1:8080')
    } else {
      authURL = new URL(ref)
    }

    const q = authURL.searchParams

    // 检查：这是 OIDC 授权码 + PKCE 的标准请求
    expect(authURL.pathname).toBe('/oauth2/auth')
    expect(q.get('client_id')).toBe('template-web-client')
    expect(q.get('response_type')).toBe('code')
    expect(q.get('redirect_uri')).toBe('http://127.0.0.1:8081/oauth/callback')
    expect(q.get('code_challenge_method')).toBe('S256')
    expect(q.get('code_challenge')).toBeTruthy()
    // S256 challenge 是 base64url(sha256)，长度固定 43
    expect(q.get('code_challenge')!.length).toBe(43)
    // state 必须存在（CSRF 防护）
    expect(q.get('state')).toBeTruthy()
    // nonce 必须存在（id_token 重放防护）
    expect(q.get('nonce')).toBeTruthy()
    // 作用域
    expect(q.get('scope')).toContain('openid')

    // 公共客户端不应出现 client_secret
    expect(authURL.search).not.toContain('client_secret')

    await page.screenshot({ path: 'screenshots/01-idp-login.png' })
  })

  test('错误密码登录被拒绝并给出提示', async ({ page }) => {
    await page.goto(BIZ + '/', { waitUntil: 'domcontentloaded' })
    await page.waitForURL(/127\.0\.0\.1:8080/, { timeout: 20_000 })
    await page.waitForSelector('input[type=text]')

    await page.fill('input[type=text]', TEST_USER.username)
    await page.fill('input[type=password]', 'definitely-wrong-password')
    await page.click('button[type=submit]')

    // 应停留在登录页并显示错误
    await expect(page.locator('text=/密码错误|账号(或邮箱)?不存在|用户名或密码/')).toBeVisible({
      timeout: 10_000,
    })
    expect(page.url()).toContain('/login')

    await page.screenshot({ path: 'screenshots/02-idp-login-error.png' })
  })

  test('账号栏填邮箱同样能登录（登录名收两种）', async ({ page }) => {
    // 管理员的身份是由 IDP_ADMIN_EMAIL 配置的邮箱，不是账号名。
    // 若登录只认账号名，配了邮箱的人会拿到一个自己登不进去的管理员 ——
    // 这条用例卡的就是这个：整条 OIDC 流程走通，而不是只看登录接口返回码。
    await loginWithPKCE(page, {
      user: { username: TEST_USER.email, password: TEST_USER.password },
    })

    expect(page.url()).toMatch(/127\.0\.0\.1:8081\/(\?.*)?$/)

    // 业务侧确实建了会话，而不是停在某个中间页。
    // 这里必须用业务站的接口：页面此刻在 8081 上，相对路径 /api/me 会打到业务后端，
    // 而它没有这个路由 —— 取到 404 会把「已登录」误判成失败。
    const profile = await fetchBizProfile(page)
    expect(profile.status).toBe(200)
  })

  test('完整 PKCE 登录流程：登录 -> 授权 -> 回调 -> 建立业务会话', async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', (e) => pageErrors.push(String(e)))

    await loginWithPKCE(page, { screenshotPrefix: '03' })

    // 回到业务首页
    expect(page.url()).toMatch(/127\.0\.0\.1:8081\/(\?.*)?$/)

    // 受保护接口可用
    const profile = await fetchBizProfile(page)
    expect(profile.status).toBe(200)

    const data = (profile.body as any).data
    expect(data).toBeTruthy()
    expect(data.username).toBe('test')
    expect(data.sub).toBeTruthy()
    // token 由后端保管，前端只能看到布尔标记
    expect(data.has_id_token).toBe(true)
    expect(data.has_refresh_token).toBe(true)

    // 页面不应出现 JS 错误（openid-client 浏览器打包问题回归）
    expect(pageErrors, `页面 JS 错误: ${pageErrors.join(' | ')}`).toHaveLength(0)

    await page.screenshot({ path: 'screenshots/04-biz-home-loggedin.png', fullPage: true })
  })

  test('登录后刷新页面，业务会话保持有效（Cookie 持久化）', async ({ page }) => {
    await loginWithPKCE(page)

    await page.reload({ waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1500)

    // 仍应停留在业务平台（不应被重新踢到 IDP）
    expect(page.url()).toContain('127.0.0.1:8081')
    const profile = await fetchBizProfile(page)
    expect(profile.status).toBe(200)
  })

  test('未登录直接访问受保护接口返回 401', async ({ page, context }) => {
    await context.clearCookies()

    // 注意：不要先访问业务首页——未登录时前端会自动发起授权跳转，
    // 导致页面离开、evaluate 的执行上下文被销毁。
    // 这里直接用 Playwright 的 request 上下文发请求，不带任何 Cookie。
    const res = await context.request.get(`${BIZ}/api/profile`)
    expect(res.status()).toBe(401)

    // 同理 /api/session 应返回 data=null
    const sessionRes = await context.request.get(`${BIZ}/api/session`)
    expect(sessionRes.status()).toBe(200)
    const body = await sessionRes.json()
    expect(body.data).toBeNull()
  })

  test('统一登出：销毁业务会话并跳转 IDP 登出', async ({ page, context }) => {
    await loginWithPKCE(page)

    // 确认已登录（此时 context 里持有业务会话 Cookie）
    expect((await fetchBizProfile(page)).status).toBe(200)

    // 点击业务平台的统一登出按钮
    const logoutBtn = page.locator('button:has-text("统一登出"), button:has-text("登出")').first()
    await expect(logoutBtn).toBeVisible({ timeout: 10_000 })
    await logoutBtn.click()

    // 登出流程：/api/logout 销毁业务会话 -> 整页跳转 IDP /oauth2/logout
    //          -> 清 IDP 会话并吊销 refresh_token -> 302 回业务首页
    // 整页跳转会重建 JS 上下文，因此这里直接用 request 上下文（复用 Cookie）
    // 发起 /api/logout 后立刻校验业务会话已失效，避免与页面跳转竞态。
    await page.waitForTimeout(1500)

    const afterLogout = await context.request.get(`${BIZ}/api/profile`)
    expect(afterLogout.status(), '登出后业务接口应返回 401').toBe(401)

    // 等待最终跳转落定
    await page
      .waitForURL(/127\.0\.0\.1:8081\/(\?.*)?$/, { timeout: 25_000 })
      .catch(() => {})

    // 业务会话必须已失效
    const statusAfterNav = await context.request.get(`${BIZ}/api/profile`)
    expect(statusAfterNav.status(), '登出后业务接口应持续返回 401').toBe(401)

    // IDP 侧全局会话也应失效：重新走授权应被要求登录
    await page.goto(BIZ + '/', { waitUntil: 'domcontentloaded' })
    await page.waitForURL(/127\.0\.0\.1:8080\//, { timeout: 20_000 })

    const finalURL = page.url()
    expect(finalURL).toContain('/login')
    const returnTo = new URL(finalURL).searchParams.get('return_to') ?? ''
    expect(returnTo).toContain('/oauth2/auth')

    await page.screenshot({ path: 'screenshots/05-idp-logout.png' })
  })
})
