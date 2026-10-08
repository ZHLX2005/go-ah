import { Page, expect } from '@playwright/test'

/** 服务地址 */
export const IDP = 'http://127.0.0.1:8080'
export const BIZ = 'http://127.0.0.1:8081'

/** 预置账号 */
export const TEST_USER = { username: 'test', password: 'test123456' }

/** 截图输出目录 */
export const SHOT_DIR = 'screenshots'

/**
 * 完成一次完整的 OIDC PKCE 登录：
 * 业务首页 -> 自动跳 IDP -> 登录表单 -> 授权确认 -> 回调 -> 业务首页
 *
 * 起始页默认是业务首页 `/`（未登录时前端会自动发起 PKCE 授权跳转）。
 */
export async function loginWithPKCE(
  page: Page,
  opts: { startPath?: string; screenshotPrefix?: string } = {},
) {
  const { startPath = '/', screenshotPrefix } = opts

  await page.goto(BIZ + startPath, { waitUntil: 'domcontentloaded' })

  // 前端检测到未登录 -> 自动构造 PKCE 参数并 302 到 IDP
  await page.waitForURL(/127\.0\.0\.1:8080/, { timeout: 20_000 })

  // 1) 登录页（若已有 IDP 会话会直接进授权页）
  if (page.url().includes('/login')) {
    await page.waitForSelector('input[type=text]')
    await page.fill('input[type=text]', TEST_USER.username)
    await page.fill('input[type=password]', TEST_USER.password)
    if (screenshotPrefix) {
      await page.screenshot({ path: `${SHOT_DIR}/${screenshotPrefix}-idp-login.png` })
    }
    await page.click('button[type=submit]')
    // 等待离开登录页
    await page.waitForURL((u) => !u.pathname.includes('/login'), { timeout: 20_000 })
  }

  // 2) 授权确认页（用精确文案定位，避免命中「拒绝授权」）
  const allowBtn = page.getByRole('button', { name: '同意授权', exact: true })
  if ((await allowBtn.count()) > 0) {
    await expect(allowBtn).toBeVisible({ timeout: 10_000 })
    if (screenshotPrefix) {
      await page.screenshot({ path: `${SHOT_DIR}/${screenshotPrefix}-idp-consent.png` })
    }
    await allowBtn.click()
  }

  // 3) 回跳业务平台（先到 /oauth/callback，前端换完 token 再回首页）
  await page.waitForURL(/127\.0\.0\.1:8081/, { timeout: 25_000 })
  await page.waitForURL(/127\.0\.0\.1:8081\/(\?.*)?$/, { timeout: 20_000 })

  if (screenshotPrefix) {
    await page.screenshot({ path: `${SHOT_DIR}/${screenshotPrefix}-biz-home.png`, fullPage: true })
  }
}

/** 读取业务侧登录态（直接调受保护接口） */
export async function fetchBizProfile(page: Page) {
  return page.evaluate(async () => {
    const r = await fetch('/api/profile', { credentials: 'include' })
    let body: unknown = null
    try {
      body = await r.json()
    } catch {
      /* 忽略非 JSON 响应 */
    }
    return { status: r.status, body }
  })
}

/** 读取 IDP 侧登录态 */
export async function fetchIDPMe(page: Page) {
  return page.evaluate(async () => {
    const r = await fetch('/api/me', { credentials: 'include' })
    let body: unknown = null
    try {
      body = await r.json()
    } catch {
      /* 忽略 */
    }
    return { status: r.status, body }
  })
}

/** 断言两个服务都可用，否则给出清晰提示 */
export async function assertServicesUp(page: Page) {
  const idp = await page
    .request.get(`${IDP}/.well-known/openid-configuration`)
    .then((r) => r.status())
    .catch(() => 0)
  const biz = await page
    .request.get(`${BIZ}/api/health`)
    .then((r) => r.status())
    .catch(() => 0)

  expect(
    idp,
    `IDP 未启动（${IDP}）。请先在 auth-hub 目录执行 go run main.go`,
  ).toBe(200)
  expect(
    biz,
    `业务平台未启动（${BIZ}）。请先在 template-business-server 目录执行 go run main.go`,
  ).toBe(200)
}
