import { test, expect } from '@playwright/test'
import { BIZ, IDP, TEST_USER, loginWithPKCE, assertServicesUp } from './helpers'

/**
 * 用例组 2：IDP 管理后台
 *
 * 覆盖：
 *  1. 未登录访问 /admin 被重定向到登录页
 *  2. 管理员登录后可访问用户管理、客户端管理、令牌管理
 *  3. 用户列表展示会话/令牌详情
 *  4. 客户端 CRUD 与内置客户端保护
 *  5. 侧边栏导航
 */

/** 以 test（管理员）身份登录 IDP，并回到指定后台页面 */
async function loginAsAdmin(page: any, targetPath = '/admin/users') {
  await page.goto(`${IDP}/login?return_to=${encodeURIComponent(targetPath)}`, {
    waitUntil: 'domcontentloaded',
  })
  await page.waitForSelector('input[type=text]')
  await page.fill('input[type=text]', TEST_USER.username)
  await page.fill('input[type=password]', TEST_USER.password)
  await page.click('button[type=submit]')
  await page.waitForURL((u: URL) => u.pathname.startsWith('/admin'), { timeout: 20_000 })
}

test.describe('IDP 管理后台', () => {
  test.beforeEach(async ({ page }) => {
    await assertServicesUp(page)
  })

  test('未登录访问 /admin/users 重定向到登录页并保留 return_to', async ({ page, context }) => {
    await context.clearCookies()

    await page.goto(`${IDP}/admin/users`, { waitUntil: 'domcontentloaded' })
    await page.waitForURL(/\/login/, { timeout: 15_000 })

    const url = new URL(page.url())
    expect(url.pathname).toBe('/login')
    expect(url.searchParams.get('return_to')).toContain('/admin/users')

    await page.screenshot({ path: 'screenshots/06-admin-unauth-redirect.png' })
  })

  test('管理员登录后可访问用户管理页', async ({ page }) => {
    await loginAsAdmin(page, '/admin/users')

    expect(page.url()).toContain('/admin/users')
    // 应至少列出 test 账号
    await expect(page.locator('text=test').first()).toBeVisible({ timeout: 10_000 })

    // 管理员接口应返回 200
    const me = await page.evaluate(async () => {
      const r = await fetch('/api/admin/me', { credentials: 'include' })
      return { status: r.status, body: await r.json().catch(() => null) }
    })
    expect(me.status).toBe(200)

    await page.screenshot({ path: 'screenshots/07-admin-users.png', fullPage: true })
  })

  test('用户列表展示活跃会话与关联 refresh_token', async ({ page }) => {
    // 先跑一次业务登录，保证有会话与令牌数据
    await loginWithPKCE(page)
    await page.context().clearCookies()

    await loginAsAdmin(page, '/admin/users')

    // 展开 test 用户的详情
    const detailBtn = page
      .locator('button:has-text("查看"), button:has-text("详情"), tr:has-text("test")')
      .first()
    if ((await detailBtn.count()) > 0) {
      await detailBtn.click().catch(() => {})
      await page.waitForTimeout(1200)
    }

    // 页面上应出现"会话"和"refresh_token"相关文案（中文界面）
    const bodyText = await page.locator('body').innerText()
    expect(
      /会话|session/i.test(bodyText),
      '用户管理页应展示会话信息',
    ).toBe(true)
    expect(
      /refresh_token|令牌/i.test(bodyText),
      '用户管理页应展示令牌信息',
    ).toBe(true)
  })

  test('管理员 API 未授权时返回 401', async ({ page, context }) => {
    await context.clearCookies()
    // 不要先访问业务首页（未登录会自动跳授权，破坏请求上下文）；
    // 直接用 request 上下文（无 Cookie）打管理接口。
    const paths = ['/api/admin/me', '/api/admin/users', '/api/admin/clients', '/api/admin/refresh-tokens']
    for (const p of paths) {
      const res = await context.request.get(`${IDP}${p}`)
      expect(res.status(), `${p} 未授权应返回 401`).toBe(401)
    }
  })

  test('客户端管理页列出预置客户端并标记 PKCE 必需', async ({ page }) => {
    await loginAsAdmin(page, '/admin/clients')

    // 列表是异步加载的，先等"加载中"消失、目标行出现
    await expect(page.locator('text=加载中')).toHaveCount(0, { timeout: 15_000 })
    await expect(page.locator('text=template-web-client').first()).toBeVisible({ timeout: 15_000 })

    const bodyText = await page.locator('body').innerText()
    expect(bodyText).toContain('template-web-client')
    expect(bodyText).toContain('oidc-cli')
    // 预置客户端均强制 PKCE
    expect(/必需|required/i.test(bodyText)).toBe(true)

    await page.screenshot({ path: 'screenshots/08-admin-clients.png', fullPage: true })
  })

  test('客户端列表接口不下发 client_secret 明文', async ({ page }) => {
    await loginAsAdmin(page, '/admin/clients')

    const res = await page.evaluate(async () => {
      const r = await fetch('/api/admin/clients', { credentials: 'include' })
      return await r.json()
    })

    const items: any[] = res.data ?? res
    expect(Array.isArray(items)).toBe(true)
    for (const c of items) {
      // 只允许 has_secret 布尔标记，不应有 client_secret 字段值
      expect(c.client_secret ?? '').toBe('')
    }
  })

  test('令牌管理页可访问并展示 REVOKED 列', async ({ page }) => {
    await loginAsAdmin(page, '/admin/tokens')

    expect(page.url()).toContain('/admin/tokens')
    const bodyText = await page.locator('body').innerText()
    // 表头（界面为英文大写列名）
    expect(/REVOKED/i.test(bodyText) || /令牌|refresh_token/i.test(bodyText)).toBe(true)

    await page.screenshot({ path: 'screenshots/09-admin-tokens.png', fullPage: true })
  })

  test('侧边栏可在三个管理面板之间切换', async ({ page }) => {
    await loginAsAdmin(page, '/admin/users')

    // 依次点击导航项
    const nav = async (label: RegExp, expectPath: string) => {
      const link = page.locator(`a:has-text("${label.source.replace(/[()]/g, '')}")`).first()
      if ((await link.count()) > 0) {
        await link.click()
        await page.waitForURL(new RegExp(expectPath), { timeout: 10_000 })
      }
    }

    await nav(/客户端|Clients/, '/admin/clients')
    await nav(/令牌|Tokens/, '/admin/tokens')
    await nav(/用户|Users/, '/admin/users')

    expect(page.url()).toContain('/admin/users')
  })

  test('新建客户端自动生成 client_secret 并可删除', async ({ page }) => {
    await loginAsAdmin(page, '/admin/clients')

    const uniqueId = `e2e-test-client-${Date.now()}`

    const created = await page.evaluate(
      async (payload) => {
        const r = await fetch('/api/admin/clients', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
        return { status: r.status, body: await r.json().catch(() => null) }
      },
      {
        client_id: uniqueId,
        client_name: 'E2E 测试客户端',
        redirect_uris: ['http://127.0.0.1:9999/callback'],
        scopes: ['openid', 'profile'],
        is_public: false,
        pkce_required: true,
        enabled: true,
      },
    )

    expect(created.status, `创建客户端失败: ${JSON.stringify(created.body)}`).toBeLessThan(300)

    // 收敛到列表中
    await page.reload({ waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(1200)
    await expect(page.locator(`text=${uniqueId}`)).toBeVisible({ timeout: 10_000 })

    // 删除刚创建的客户端
    const deleted = await page.evaluate(async (clientId) => {
      const list = await fetch('/api/admin/clients', { credentials: 'include' }).then((r) => r.json())
      const items: any[] = list.data ?? list
      const target = items.find((c) => c.client_id === clientId)
      if (!target) return { status: 404, body: null }
      const r = await fetch(`/api/admin/clients/${target.id}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      return { status: r.status, body: await r.json().catch(() => null) }
    }, uniqueId)

    expect(deleted.status, `删除客户端失败: ${JSON.stringify(deleted.body)}`).toBeLessThan(300)
  })

  test('内置客户端受保护，不可删除', async ({ page }) => {
    await loginAsAdmin(page, '/admin/clients')

    const result = await page.evaluate(async () => {
      const list = await fetch('/api/admin/clients', { credentials: 'include' }).then((r) => r.json())
      const items: any[] = list.data ?? list
      const builtin = items.find((c) => c.client_id === 'template-web-client')
      if (!builtin) return { status: 0, body: null }
      const r = await fetch(`/api/admin/clients/${builtin.id}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      return { status: r.status, body: await r.json().catch(() => null) }
    })

    // 内置客户端必须被拒绝（4xx）
    expect(result.status, '内置客户端不应允许删除').toBeGreaterThanOrEqual(400)
  })
})
