import { test, expect } from '@playwright/test'
import {
  BIZ,
  IDP,
  loginWithPKCE,
  resetBrowserSession,
  fetchBizProfile,
  assertServicesUp,
} from './helpers'

/**
 * 用例组 3：令牌生命周期（刷新与吊销）
 *
 * 说明：
 *  - 需要浏览器会话态的用例（依赖业务 HttpOnly Cookie）走 page。
 *  - 纯协议层断言（IDP token/userinfo 端点）走 Playwright 的 request 上下文，
 *    避免浏览器同源策略（IDP:8080 与业务:8081 跨域，page 内 fetch 会被 CORS 拦截）。
 */

/** 提交表单到指定地址（form-urlencoded） */
async function postForm(
  req: import('@playwright/test').APIRequestContext,
  url: string,
  form: Record<string, string>,
) {
  const body = new URLSearchParams(form).toString()
  return req.post(url, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: body,
  })
}

test.describe('令牌生命周期（刷新与吊销）', () => {
  test('登录后受保护接口暴露加密标记与正确的 TTL', async ({ page }) => {
    await assertServicesUp(page)
    await loginWithPKCE(page)

    const profile = await fetchBizProfile(page)
    expect(profile.status).toBe(200)

    const d = (profile.body as any).data
    // Task4：token 加密存储标记
    expect(d.token_encrypted, '应标记 token 已加密').toBe(true)
    expect(d.has_refresh_token).toBe(true)
    expect(d.has_id_token).toBe(true)

    // access_token 剩余 TTL 应接近 10 分钟
    const accTtlMin = (new Date(d.access_token_expires_at).getTime() - Date.now()) / 60000
    expect(accTtlMin).toBeGreaterThan(8)
    expect(accTtlMin).toBeLessThanOrEqual(10.2)

    // refresh_token 剩余 TTL 应接近 7 天
    const refTtlDay = (new Date(d.refresh_token_expires_at).getTime() - Date.now()) / 86400000
    expect(refTtlDay).toBeGreaterThan(6.9)
    expect(refTtlDay).toBeLessThanOrEqual(7.05)
  })

  test('业务侧手动刷新接口可换取新令牌', async ({ page }) => {
    await assertServicesUp(page)
    await loginWithPKCE(page)

    const before = await fetchBizProfile(page)
    expect(before.status).toBe(200)
    const beforeExp = new Date((before.body as any).data.access_token_expires_at).getTime()

    // 等待 1.1 秒，确保新令牌的过期时间严格更晚
    await page.waitForTimeout(1100)

    const refreshed = await page.evaluate(async () => {
      const r = await fetch('/api/refresh', { method: 'POST', credentials: 'include' })
      return { status: r.status, body: await r.json().catch(() => null) }
    })
    expect(refreshed.status, `刷新失败: ${JSON.stringify(refreshed.body)}`).toBe(200)

    const after = await fetchBizProfile(page)
    expect(after.status).toBe(200)
    const afterExp = new Date((after.body as any).data.access_token_expires_at).getTime()

    // 过期时间应被推后
    expect(afterExp).toBeGreaterThan(beforeExp)
    // 仍应是加密存储
    expect((after.body as any).data.token_encrypted).toBe(true)
  })

  test('管理员吊销 refresh_token 后，IDP 拒绝该令牌', async ({ page, request }) => {
    await assertServicesUp(page)
    await loginWithPKCE(page)

    // 1) 业务侧先成功刷新一次，确认链路正常
    const ok = await page.evaluate(async () => {
      const r = await fetch('/api/refresh', { method: 'POST', credentials: 'include' })
      return r.status
    })
    expect(ok).toBe(200)

    // 2) 以管理员身份登录管理后台并吊销全部有效 refresh_token
    //    走 resetBrowserSession：直接 clearCookies 会被业务 SPA 的自动授权
    //    跳转抢走下面的 goto（同一个竞态，见 helpers 里的说明）
    await resetBrowserSession(page)
    await page.goto(`${IDP}/login?return_to=${encodeURIComponent('/admin/tokens')}`, {
      waitUntil: 'domcontentloaded',
    })
    await page.waitForSelector('input[type=text]')
    await page.fill('input[type=text]', 'test')
    await page.fill('input[type=password]', 'test123456')
    await page.click('button[type=submit]')
    await page.waitForURL((u: URL) => u.pathname.startsWith('/admin'), { timeout: 20_000 })

    const revoked = await page.evaluate(async () => {
      const list = await fetch('/api/admin/refresh-tokens', { credentials: 'include' }).then((r) =>
        r.json(),
      )
      const items: any[] = list.data ?? list
      const active = items.filter((t) => !t.revoked && !t.revoked_at)
      let count = 0
      for (const t of active) {
        // 后端契约：{"id": <数字主键>} 或 {"token": "完整令牌"}
        const r = await fetch('/api/admin/revoke-token', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: t.id }),
        })
        if (r.ok) count++
      }
      return { total: items.length, active: active.length, revoked: count }
    })
    expect(revoked.revoked, `吊销失败: ${JSON.stringify(revoked)}`).toBeGreaterThan(0)

    // 3) 用被吊销的令牌打 IDP token 端点，应 400 invalid_grant
    const grantResult = await postForm(request, `${IDP}/oauth2/token`, {
      grant_type: 'refresh_token',
      refresh_token: 'revoked-or-unknown-token',
      client_id: 'template-web-client',
    })
    expect(grantResult.status()).toBe(400)
    const grantBody = await grantResult.json()
    expect(grantBody.error).toBe('invalid_grant')

    await page.screenshot({ path: 'screenshots/10-admin-tokens-revoked.png', fullPage: true })
  })

  test('IDP 令牌端点：不存在的 refresh_token 返回 invalid_grant', async ({ request }) => {
    const res = await postForm(request, `${IDP}/oauth2/token`, {
      grant_type: 'refresh_token',
      refresh_token: 'totally-made-up-token',
      client_id: 'template-web-client',
    })

    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('invalid_grant')
  })

  test('userinfo 端点：无 Bearer 令牌 / 伪造令牌均 401', async ({ request }) => {
    const noAuth = await request.get(`${IDP}/oauth2/userinfo`)
    expect(noAuth.status()).toBe(401)

    const badAuth = await request.get(`${IDP}/oauth2/userinfo`, {
      headers: { Authorization: 'Bearer not-a-real-token' },
    })
    expect(badAuth.status()).toBe(401)
  })

  test('授权码重复使用 / 伪造授权码被拒绝（invalid_grant）', async ({ request }) => {
    const res = await postForm(request, `${IDP}/oauth2/token`, {
      grant_type: 'authorization_code',
      code: 'already-used-or-fake-code',
      redirect_uri: 'http://127.0.0.1:8081/oauth/callback',
      client_id: 'template-web-client',
      code_verifier: 'some-verifier-value-that-is-long-enough-1234567890',
    })

    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('invalid_grant')
  })

  test('业务安全状态接口暴露加密与续期参数（且不泄漏密钥）', async ({ request }) => {
    const res = await request.get(`${BIZ}/api/security-status`)
    expect(res.status()).toBe(200)

    const b = await res.json()
    expect(b.token_encryption.algorithm).toBe('AES-256-GCM')
    expect(b.token_encryption.kdf).toBe('PBKDF2-HMAC-SHA256')
    expect(b.token_encryption.key_source).toBe('env:BIZ_TOKEN_SECRET')
    expect(b.token_encryption.ready).toBe(true)

    expect(b.auto_refresh.enabled).toBe(true)
    expect(b.auto_refresh.access_token_ttl).toBe('10m')
    expect(b.auto_refresh.threshold).toBe('2m')

    // 只暴露算法与参数，不应包含密钥本体
    const serialized = JSON.stringify(b)
    expect(serialized).not.toContain('BIZ_TOKEN_SECRET=')
    expect(serialized).not.toMatch(/secret"\s*:\s*"[A-Za-z0-9+/=]{16,}"/)
  })

  test('登出后业务会话失效（/api/profile 401）', async ({ page, context }) => {
    await assertServicesUp(page)
    await loginWithPKCE(page)
    expect((await fetchBizProfile(page)).status).toBe(200)

    // 业务侧登出
    const logoutRes = await context.request.post(`${BIZ}/api/logout`)
    expect(logoutRes.status()).toBe(200)

    // 会话 Cookie 已清除 -> 受保护接口 401
    const after = await context.request.get(`${BIZ}/api/profile`)
    expect(after.status()).toBe(401)
  })
})
